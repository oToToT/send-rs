use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tokio::{fs, sync::RwLock};

use crate::{AppError, AppResult, Config, auth};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
}

impl AppState {
    pub async fn new(config: Config) -> AppResult<Self> {
        let store = Store::new(config.file_dir.clone()).await?;
        Ok(Self {
            config: Arc::new(config),
            store: Arc::new(store),
        })
    }
}

#[derive(Clone, Debug)]
pub struct FileRecord {
    pub owner: String,
    pub metadata: String,
    pub dlimit: u32,
    pub dl: u32,
    pub auth: String,
    pub nonce: String,
    pub pwd: bool,
    pub expires_at: SystemTime,
    pub blob_path: PathBuf,
}

#[derive(Deserialize, Serialize)]
struct PersistedRecord {
    owner: String,
    metadata: String,
    dlimit: u32,
    dl: u32,
    auth: String,
    nonce: String,
    pwd: bool,
    expires_at_unix_ms: u128,
}

pub struct NewFile {
    pub id: String,
    pub owner: String,
    pub metadata: String,
    pub dlimit: u32,
    pub auth: String,
    pub ttl: Duration,
    pub bytes: Vec<u8>,
}

pub struct Store {
    dir: PathBuf,
    files_dir: PathBuf,
    records_dir: PathBuf,
    records: RwLock<HashMap<String, FileRecord>>,
}

impl Store {
    pub async fn new(dir: PathBuf) -> AppResult<Self> {
        let files_dir = dir.join("files");
        let records_dir = dir.join("records");
        fs::create_dir_all(&files_dir).await?;
        fs::create_dir_all(&records_dir).await?;
        let store = Self {
            dir,
            files_dir,
            records_dir,
            records: RwLock::new(HashMap::new()),
        };
        store.load_records().await?;
        store.cleanup_expired().await;
        Ok(store)
    }

    pub async fn create(&self, file: NewFile) -> AppResult<FileRecord> {
        self.cleanup_expired().await;
        let blob_path = self.files_dir.join(&file.id);
        fs::write(&blob_path, &file.bytes).await?;
        let record = FileRecord {
            owner: file.owner,
            metadata: file.metadata,
            dlimit: file.dlimit,
            dl: 0,
            auth: file.auth,
            nonce: auth::new_nonce(),
            pwd: false,
            expires_at: SystemTime::now() + file.ttl,
            blob_path,
        };
        if let Err(err) = self.persist_record(&file.id, &record).await {
            let _ = fs::remove_file(&record.blob_path).await;
            return Err(err);
        }
        self.records.write().await.insert(file.id, record.clone());
        Ok(record)
    }

    pub async fn get(&self, id: &str) -> Option<FileRecord> {
        self.cleanup_expired().await;
        self.records.read().await.get(id).cloned()
    }

    pub async fn ttl_ms(&self, id: &str) -> AppResult<u64> {
        let record = self.get(id).await.ok_or(AppError::NotFound)?;
        Ok(record
            .expires_at
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            .as_millis() as u64)
    }

    pub async fn read_blob(&self, id: &str) -> AppResult<Vec<u8>> {
        let record = self.get(id).await.ok_or(AppError::NotFound)?;
        Ok(fs::read(record.blob_path).await?)
    }

    pub async fn rotate_nonce(&self, id: &str) -> AppResult<String> {
        let nonce = auth::new_nonce();
        let record = {
            let mut records = self.records.write().await;
            let record = records.get_mut(id).ok_or(AppError::NotFound)?;
            record.nonce = nonce.clone();
            record.clone()
        };
        self.persist_record(id, &record).await?;
        Ok(nonce)
    }

    pub async fn set_password(&self, id: &str, auth_key: String) -> AppResult<()> {
        let record = {
            let mut records = self.records.write().await;
            let record = records.get_mut(id).ok_or(AppError::NotFound)?;
            record.auth = auth_key;
            record.pwd = true;
            record.clone()
        };
        self.persist_record(id, &record).await
    }

    pub async fn set_download_limit(&self, id: &str, dlimit: u32) -> AppResult<()> {
        let record = {
            let mut records = self.records.write().await;
            let record = records.get_mut(id).ok_or(AppError::NotFound)?;
            record.dlimit = dlimit;
            record.clone()
        };
        self.persist_record(id, &record).await
    }

    pub async fn mark_download_complete(&self, id: &str) -> AppResult<()> {
        let mut delete_path = None;
        let mut updated = None;
        {
            let mut records = self.records.write().await;
            let record = records.get_mut(id).ok_or(AppError::NotFound)?;
            let next = record.dl.saturating_add(1);
            if next >= record.dlimit {
                delete_path = Some(record.blob_path.clone());
                records.remove(id);
            } else {
                record.dl = next;
                updated = Some(record.clone());
            }
        }
        if let Some(path) = delete_path {
            let _ = fs::remove_file(path).await;
            let _ = fs::remove_file(self.record_path(id)).await;
        } else if let Some(record) = updated {
            self.persist_record(id, &record).await?;
        }
        Ok(())
    }

    pub async fn delete(&self, id: &str) -> AppResult<()> {
        let path = self.records.write().await.remove(id).map(|r| r.blob_path);
        if let Some(path) = path {
            let _ = fs::remove_file(path).await;
            let _ = fs::remove_file(self.record_path(id)).await;
            Ok(())
        } else {
            Err(AppError::NotFound)
        }
    }

    pub async fn ping(&self) -> AppResult<()> {
        fs::create_dir_all(&self.files_dir).await?;
        fs::create_dir_all(&self.records_dir).await?;
        let probe = self.dir.join(".heartbeat");
        fs::write(&probe, b"ok").await?;
        let _ = fs::remove_file(probe).await;
        Ok(())
    }

    async fn cleanup_expired(&self) {
        let now = SystemTime::now();
        let mut expired = Vec::new();
        {
            let mut records = self.records.write().await;
            records.retain(|id, record| {
                if record.expires_at <= now {
                    expired.push((id.clone(), record.blob_path.clone()));
                    false
                } else {
                    true
                }
            });
        }
        for (id, path) in expired {
            let _ = fs::remove_file(path).await;
            let _ = fs::remove_file(self.record_path(&id)).await;
        }
    }

    async fn load_records(&self) -> AppResult<()> {
        let mut entries = fs::read_dir(&self.records_dir).await?;
        let mut records = self.records.write().await;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|name| name.to_str()) else {
                continue;
            };
            let raw = fs::read(&path).await?;
            let persisted: PersistedRecord = serde_json::from_slice(&raw).map_err(|err| {
                AppError::Storage(format!("invalid record {}: {err}", path.display()))
            })?;
            let expires_at = UNIX_EPOCH
                + Duration::from_millis(persisted.expires_at_unix_ms.min(u64::MAX as u128) as u64);
            let blob_path = self.files_dir.join(id);
            if fs::try_exists(&blob_path).await? {
                records.insert(
                    id.to_string(),
                    FileRecord {
                        owner: persisted.owner,
                        metadata: persisted.metadata,
                        dlimit: persisted.dlimit,
                        dl: persisted.dl,
                        auth: persisted.auth,
                        nonce: persisted.nonce,
                        pwd: persisted.pwd,
                        expires_at,
                        blob_path,
                    },
                );
            } else {
                let _ = fs::remove_file(path).await;
            }
        }
        Ok(())
    }

    async fn persist_record(&self, id: &str, record: &FileRecord) -> AppResult<()> {
        let persisted = PersistedRecord {
            owner: record.owner.clone(),
            metadata: record.metadata.clone(),
            dlimit: record.dlimit,
            dl: record.dl,
            auth: record.auth.clone(),
            nonce: record.nonce.clone(),
            pwd: record.pwd,
            expires_at_unix_ms: record
                .expires_at
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        };
        let bytes =
            serde_json::to_vec(&persisted).map_err(|err| AppError::Storage(err.to_string()))?;
        let path = self.record_path(id);
        let temp = path.with_extension("json.tmp");
        fs::write(&temp, bytes).await?;
        fs::rename(temp, path).await?;
        Ok(())
    }

    fn record_path(&self, id: &str) -> PathBuf {
        self.records_dir.join(format!("{id}.json"))
    }
}
