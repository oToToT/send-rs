use std::{
    collections::HashSet,
    fs::OpenOptions,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, params};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
};

use crate::{AppError, AppResult, Config, auth, ids};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
    pub auth_throttle: Arc<auth::AuthThrottle>,
}

impl AppState {
    pub async fn new(config: Config) -> AppResult<Self> {
        let store = Arc::new(Store::new(config.file_dir.clone()).await?);
        spawn_cleanup_worker(Arc::downgrade(&store));
        Ok(Self {
            config: Arc::new(config),
            store,
            auth_throttle: Arc::new(auth::AuthThrottle::default()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct FileRecord {
    pub owner_hash: String,
    pub metadata: String,
    pub dlimit: u32,
    pub dl: u32,
    pub auth: String,
    pub nonce: String,
    pub pwd: bool,
    pub expires_at: SystemTime,
    pub blob_path: PathBuf,
    pub blob_size: u64,
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

pub struct NewFileRecord {
    pub id: String,
    pub owner: String,
    pub metadata: String,
    pub dlimit: u32,
    pub auth: String,
    pub ttl: Duration,
}

pub struct PendingUpload {
    path: PathBuf,
    file: File,
    size: u64,
}

impl PendingUpload {
    pub async fn write(&mut self, bytes: &[u8]) -> AppResult<()> {
        self.file.write_all(bytes).await?;
        self.size = self.size.saturating_add(bytes.len() as u64);
        Ok(())
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

pub struct OpenBlob {
    pub file: File,
    pub size: u64,
}

pub struct Store {
    files_dir: PathBuf,
    tmp_dir: PathBuf,
    db: Arc<Mutex<Connection>>,
    owner_key: Arc<[u8; 32]>,
    _lock_file: std::fs::File,
}

impl Store {
    pub async fn new(dir: PathBuf) -> AppResult<Self> {
        let files_dir = dir.join("files");
        let tmp_dir = dir.join("tmp");
        fs::create_dir_all(&files_dir).await?;
        fs::create_dir_all(&tmp_dir).await?;
        set_private_dir_permissions(&dir).await?;
        set_private_dir_permissions(&files_dir).await?;
        set_private_dir_permissions(&tmp_dir).await?;
        let lock_path = dir.join("storage.lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        lock_file.try_lock_exclusive().map_err(|error| {
            AppError::Storage(format!(
                "FILE_DIR is already in use by another server: {error}"
            ))
        })?;
        set_private_file_permissions(&lock_path).await?;

        let db_path = dir.join("metadata.sqlite3");
        if fs::try_exists(dir.join("records")).await? {
            return Err(AppError::Storage(
                "legacy JSON storage detected; use an empty FILE_DIR".into(),
            ));
        }
        if !fs::try_exists(&db_path).await? {
            let mut existing_blobs = fs::read_dir(&files_dir).await?;
            if existing_blobs.next_entry().await?.is_some() {
                return Err(AppError::Storage(
                    "blob files exist without a metadata database; use an empty FILE_DIR".into(),
                ));
            }
        }
        let owner_key = load_or_create_owner_key(&dir.join("owner-token.key")).await?;
        sync_directory(dir.clone()).await?;
        let connection = tokio::task::spawn_blocking(move || -> AppResult<Connection> {
            let connection = Connection::open(db_path)?;
            connection.busy_timeout(Duration::from_secs(5))?;
            connection.pragma_update(None, "journal_mode", "WAL")?;
            connection.pragma_update(None, "synchronous", "FULL")?;
            connection.execute_batch(
                "CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY NOT NULL,
                    owner_hash TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    dlimit INTEGER NOT NULL CHECK(dlimit > 0),
                    dl INTEGER NOT NULL DEFAULT 0 CHECK(dl >= 0),
                    auth TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    pwd INTEGER NOT NULL DEFAULT 0 CHECK(pwd IN (0, 1)),
                    expires_at_ms INTEGER NOT NULL,
                    blob_size INTEGER NOT NULL CHECK(blob_size >= 0)
                ) STRICT;
                CREATE INDEX IF NOT EXISTS files_expires_at ON files(expires_at_ms);",
            )?;
            Ok(connection)
        })
        .await
        .map_err(|err| AppError::Storage(err.to_string()))??;
        set_private_file_permissions(&dir.join("metadata.sqlite3")).await?;
        sync_directory(dir.clone()).await?;

        let store = Self {
            files_dir,
            tmp_dir,
            db: Arc::new(Mutex::new(connection)),
            owner_key: Arc::new(owner_key),
            _lock_file: lock_file,
        };
        store.reconcile().await?;
        store.cleanup_expired().await?;
        Ok(store)
    }

    pub async fn start_upload(&self, id: &str) -> AppResult<PendingUpload> {
        ids::validate_file_id(id)?;
        let path = self
            .tmp_dir
            .join(format!("{id}-{}.partial", ids::random_hex(8)));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        set_private_file_permissions(&path).await?;
        Ok(PendingUpload {
            path,
            file: File::from_std(file),
            size: 0,
        })
    }

    pub async fn abort_upload(&self, upload: PendingUpload) {
        drop(upload.file);
        let _ = fs::remove_file(upload.path).await;
    }

    pub async fn commit_upload(
        &self,
        file: NewFileRecord,
        mut upload: PendingUpload,
    ) -> AppResult<FileRecord> {
        ids::validate_file_id(&file.id)?;
        let owner_hash = auth::owner_token_digest(self.owner_key.as_ref(), &file.owner)?;
        upload.file.flush().await?;
        upload.file.sync_all().await?;
        drop(upload.file);

        let blob_path = self.files_dir.join(&file.id);
        if fs::try_exists(&blob_path).await? {
            let _ = fs::remove_file(&upload.path).await;
            return Err(AppError::Storage("file id collision".into()));
        }
        fs::rename(&upload.path, &blob_path).await?;
        sync_directory(self.files_dir.clone()).await?;

        let record = FileRecord {
            owner_hash,
            metadata: file.metadata,
            dlimit: file.dlimit,
            dl: 0,
            auth: file.auth,
            nonce: auth::new_nonce(),
            pwd: false,
            expires_at: SystemTime::now() + file.ttl,
            blob_path: blob_path.clone(),
            blob_size: upload.size,
        };

        let insert = self.insert_record(&file.id, &record).await;
        if let Err(err) = insert {
            let _ = fs::remove_file(blob_path).await;
            return Err(err);
        }
        Ok(record)
    }

    pub async fn create(&self, file: NewFile) -> AppResult<FileRecord> {
        let mut upload = self.start_upload(&file.id).await?;
        if let Err(err) = upload.write(&file.bytes).await {
            self.abort_upload(upload).await;
            return Err(err);
        }
        self.commit_upload(
            NewFileRecord {
                id: file.id,
                owner: file.owner,
                metadata: file.metadata,
                dlimit: file.dlimit,
                auth: file.auth,
                ttl: file.ttl,
            },
            upload,
        )
        .await
    }

    pub async fn get(&self, id: &str) -> Option<FileRecord> {
        if self.cleanup_expired().await.is_err() {
            return None;
        }
        self.get_result(id).await.ok().flatten()
    }

    pub async fn ttl_ms(&self, id: &str) -> AppResult<u64> {
        let record = self.get_result(id).await?.ok_or(AppError::NotFound)?;
        Ok(record
            .expires_at
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            .as_millis() as u64)
    }

    pub async fn open_blob(&self, id: &str) -> AppResult<OpenBlob> {
        let record = self.get_result(id).await?.ok_or(AppError::NotFound)?;
        let file = File::open(&record.blob_path).await?;
        Ok(OpenBlob {
            file,
            size: record.blob_size,
        })
    }

    pub async fn read_blob(&self, id: &str) -> AppResult<Vec<u8>> {
        let record = self.get_result(id).await?.ok_or(AppError::NotFound)?;
        Ok(fs::read(record.blob_path).await?)
    }

    pub async fn rotate_nonce_if(&self, id: &str, previous: &str) -> AppResult<String> {
        let id = id.to_owned();
        let previous = previous.to_owned();
        let nonce = auth::new_nonce();
        let next = nonce.clone();
        let changed = self
            .with_db(move |db| {
                Ok(db.execute(
                    "UPDATE files SET nonce = ?1
                     WHERE id = ?2 AND nonce = ?3 AND expires_at_ms > ?4 AND dl < dlimit",
                    params![next, id, previous, now_ms()],
                )?)
            })
            .await?;
        if changed == 1 {
            Ok(nonce)
        } else {
            Err(AppError::Unauthorized)
        }
    }

    pub async fn set_password(&self, id: &str, auth_key: String) -> AppResult<()> {
        self.update_one(
            "UPDATE files SET auth = ?1, pwd = 1 WHERE id = ?2 AND expires_at_ms > ?3",
            auth_key,
            id,
        )
        .await
    }

    pub async fn verify_owner(&self, id: &str, provided: &str) -> AppResult<FileRecord> {
        let record = self.get_result(id).await?.ok_or(AppError::NotFound)?;
        auth::verify_owner_digest(self.owner_key.as_ref(), &record.owner_hash, provided)?;
        Ok(record)
    }

    pub async fn set_download_limit(&self, id: &str, dlimit: u32) -> AppResult<()> {
        let id = id.to_owned();
        let changed = self
            .with_db(move |db| {
                Ok(db.execute(
                    "UPDATE files SET dlimit = ?1
                     WHERE id = ?2 AND expires_at_ms > ?3 AND dl < ?1",
                    params![i64::from(dlimit), id, now_ms()],
                )?)
            })
            .await?;
        if changed == 1 {
            Ok(())
        } else {
            Err(AppError::NotFound)
        }
    }

    /// Claims a download before it is streamed. Aborted downloads count toward
    /// the limit, which guarantees that a one-download link cannot be raced.
    pub async fn claim_download(&self, id: &str) -> AppResult<bool> {
        let id_owned = id.to_owned();
        let result = self
            .with_db(move |db| {
                let tx = db.transaction()?;
                let counts = tx
                    .query_row(
                        "SELECT dl, dlimit FROM files
                         WHERE id = ?1 AND expires_at_ms > ?2 AND dl < dlimit",
                        params![id_owned, now_ms()],
                        |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?)),
                    )
                    .optional()?;
                let Some((dl, limit)) = counts else {
                    return Ok(None);
                };
                let final_download = dl.saturating_add(1) >= limit;
                if final_download {
                    tx.execute("DELETE FROM files WHERE id = ?1", params![id_owned])?;
                } else {
                    tx.execute(
                        "UPDATE files SET dl = dl + 1 WHERE id = ?1",
                        params![id_owned],
                    )?;
                }
                tx.commit()?;
                Ok(Some(final_download))
            })
            .await?
            .ok_or(AppError::NotFound)?;

        if result {
            let _ = fs::remove_file(self.files_dir.join(id)).await;
            let _ = sync_directory(self.files_dir.clone()).await;
        }
        Ok(result)
    }

    pub async fn delete(&self, id: &str) -> AppResult<()> {
        let id_owned = id.to_owned();
        let changed = self
            .with_db(move |db| Ok(db.execute("DELETE FROM files WHERE id = ?1", [id_owned])?))
            .await?;
        if changed == 0 {
            return Err(AppError::NotFound);
        }
        let _ = fs::remove_file(self.files_dir.join(id)).await;
        sync_directory(self.files_dir.clone()).await?;
        Ok(())
    }

    pub async fn ping(&self) -> AppResult<()> {
        self.with_db(|db| {
            db.query_row("PRAGMA quick_check", [], |row| {
                let result: String = row.get(0)?;
                if result == "ok" {
                    Ok(())
                } else {
                    Err(rusqlite::Error::InvalidQuery)
                }
            })?;
            Ok(())
        })
        .await?;
        let probe = self
            .tmp_dir
            .join(format!(".heartbeat-{}", ids::random_hex(8)));
        let mut file = File::create(&probe).await?;
        file.write_all(b"ok").await?;
        file.sync_all().await?;
        fs::remove_file(probe).await?;
        Ok(())
    }

    async fn insert_record(&self, id: &str, record: &FileRecord) -> AppResult<()> {
        let id = id.to_owned();
        let record = record.clone();
        self.with_db(move |db| {
            db.execute(
                "INSERT INTO files
                 (id, owner_hash, metadata, dlimit, dl, auth, nonce, pwd, expires_at_ms, blob_size)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    id,
                    record.owner_hash,
                    record.metadata,
                    i64::from(record.dlimit),
                    i64::from(record.dl),
                    record.auth,
                    record.nonce,
                    record.pwd,
                    system_time_ms(record.expires_at),
                    record.blob_size as i64,
                ],
            )?;
            Ok(())
        })
        .await
    }

    async fn get_result(&self, id: &str) -> AppResult<Option<FileRecord>> {
        let id = id.to_owned();
        let files_dir = self.files_dir.clone();
        self.with_db(move |db| {
            let record = db
                .query_row(
                    "SELECT owner_hash, metadata, dlimit, dl, auth, nonce, pwd,
                            expires_at_ms, blob_size
                     FROM files
                     WHERE id = ?1 AND expires_at_ms > ?2 AND dl < dlimit",
                    params![id, now_ms()],
                    |row| {
                        let expires_at_ms: i64 = row.get(7)?;
                        Ok(FileRecord {
                            owner_hash: row.get(0)?,
                            metadata: row.get(1)?,
                            dlimit: row.get(2)?,
                            dl: row.get(3)?,
                            auth: row.get(4)?,
                            nonce: row.get(5)?,
                            pwd: row.get(6)?,
                            expires_at: UNIX_EPOCH
                                + Duration::from_millis(expires_at_ms.max(0) as u64),
                            blob_path: files_dir.join(&id),
                            blob_size: row.get::<_, i64>(8)?.max(0) as u64,
                        })
                    },
                )
                .optional()?;
            Ok(record)
        })
        .await
    }

    async fn update_one(&self, sql: &'static str, value: String, id: &str) -> AppResult<()> {
        let id = id.to_owned();
        let changed = self
            .with_db(move |db| Ok(db.execute(sql, params![value, id, now_ms()])?))
            .await?;
        if changed == 1 {
            Ok(())
        } else {
            Err(AppError::NotFound)
        }
    }

    async fn cleanup_expired(&self) -> AppResult<()> {
        let expired = self
            .with_db(|db| {
                let mut statement =
                    db.prepare("DELETE FROM files WHERE expires_at_ms <= ?1 RETURNING id")?;
                let ids = statement
                    .query_map([now_ms()], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ids)
            })
            .await?;
        for id in expired {
            let _ = fs::remove_file(self.files_dir.join(id)).await;
        }
        Ok(())
    }

    async fn reconcile(&self) -> AppResult<()> {
        let mut temporary = fs::read_dir(&self.tmp_dir).await?;
        while let Some(entry) = temporary.next_entry().await? {
            if entry.file_type().await?.is_file() {
                let _ = fs::remove_file(entry.path()).await;
            }
        }

        let known = self
            .with_db(|db| {
                let mut statement = db.prepare("SELECT id FROM files")?;
                let ids = statement
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<HashSet<_>, _>>()?;
                Ok(ids)
            })
            .await?;
        let mut missing = Vec::new();
        for id in &known {
            if !fs::try_exists(self.files_dir.join(id)).await? {
                missing.push(id.clone());
            }
        }
        if !missing.is_empty() {
            self.with_db(move |db| {
                let tx = db.transaction()?;
                for id in missing {
                    tx.execute("DELETE FROM files WHERE id = ?1", [id])?;
                }
                tx.commit()?;
                Ok(())
            })
            .await?;
        }
        let mut blobs = fs::read_dir(&self.files_dir).await?;
        while let Some(entry) = blobs.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type().await?.is_file() && !known.contains(&name) {
                let _ = fs::remove_file(entry.path()).await;
            }
        }
        Ok(())
    }

    async fn with_db<T, F>(&self, operation: F) -> AppResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> AppResult<T> + Send + 'static,
    {
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || {
            let mut connection = db
                .lock()
                .map_err(|_| AppError::Storage("metadata lock poisoned".into()))?;
            operation(&mut connection)
        })
        .await
        .map_err(|err| AppError::Storage(err.to_string()))?
    }
}

fn spawn_cleanup_worker(store: Weak<Store>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            let Some(store) = store.upgrade() else {
                return;
            };
            if let Err(error) = store.cleanup_expired().await {
                tracing::warn!(%error, "expired-file cleanup failed");
            }
        }
    });
}

fn now_ms() -> i64 {
    system_time_ms(SystemTime::now())
}

fn system_time_ms(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

async fn sync_directory(path: PathBuf) -> AppResult<()> {
    #[cfg(unix)]
    tokio::task::spawn_blocking(move || OpenOptions::new().read(true).open(path)?.sync_all())
        .await
        .map_err(|err| AppError::Storage(err.to_string()))??;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

async fn set_private_dir_permissions(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    }
    Ok(())
}

async fn set_private_file_permissions(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    Ok(())
}

async fn load_or_create_owner_key(path: &Path) -> AppResult<[u8; 32]> {
    match File::open(path).await {
        Ok(mut file) => {
            let mut key = [0_u8; 32];
            file.read_exact(&mut key).await?;
            let mut extra = [0_u8; 1];
            if file.read(&mut extra).await? != 0 {
                return Err(AppError::Storage(
                    "owner-token key has invalid length".into(),
                ));
            }
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            use rand::RngCore;
            let mut key = [0_u8; 32];
            rand::rng().fill_bytes(&mut key);
            let file = OpenOptions::new().write(true).create_new(true).open(path)?;
            set_private_file_permissions(path).await?;
            let mut file = File::from_std(file);
            file.write_all(&key).await?;
            file.sync_all().await?;
            Ok(key)
        }
        Err(error) => Err(error.into()),
    }
}
