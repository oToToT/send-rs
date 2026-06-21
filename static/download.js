(function () {
  'use strict';

  var sendCrypto = window.SendCrypto;

  function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = 0;
    var size = bytes;
    while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
    return i === 0 ? bytes + ' ' + units[i] : size.toFixed(1) + ' ' + units[i];
  }

  async function initDownloadPage() {
    var panel = document.querySelector('.download-panel');
    if (!panel || panel.dataset.downloadReady === 'true') return;

    var fileId = panel.getAttribute('data-file-id');
    if (!fileId) { panel.dataset.downloadReady = 'true'; return; }

    var keyB64 = location.hash.replace(/^#/, '');
    var downloadBtn = document.getElementById('download-btn');
    var passwordForm = document.getElementById('password-form');
    var passwordInput = document.getElementById('password-input');
    var passwordBtn = document.getElementById('password-btn');
    var passwordError = document.getElementById('password-error');
    var shareUrlInput = document.getElementById('share-url');
    var qrBtn = document.getElementById('qr-btn');

    if (passwordForm && !(window.downloadMetadata && window.downloadMetadata.pwd)) {
      passwordForm.hidden = true;
    }

    if (!keyB64) {
      if (passwordForm) passwordForm.hidden = true;
      if (downloadBtn) downloadBtn.hidden = true;
      if (shareUrlInput) shareUrlInput.hidden = true;
      if (qrBtn) qrBtn.hidden = true;
      panel.dataset.downloadReady = 'true';
      return;
    }

    var secretKey = sendCrypto.b64Decode(keyB64);
    var metadata = null;
    var authentication = null;

    try {
      authentication = await sendCrypto.deriveAuthenticationBytes(secretKey);
    } catch (e) {
      showError('Cannot process encryption key');
      panel.dataset.downloadReady = 'true';
      return;
    }

    async function getNonce() {
      var res = await fetch('/api/exists/' + fileId);
      if (res.status === 404) { showError('Link not found or expired'); return null; }
      var auth = res.headers.get('WWW-Authenticate');
      if (!auth || !auth.startsWith('send-v1 ')) return null;
      return auth.slice(8);
    }

    async function computeHmac(nonceB64) {
      var nonce = sendCrypto.b64Decode(nonceB64);
      var sig = await sendCrypto.signNonce(authentication, nonce);
      return sendCrypto.b64Encode(sig);
    }

    async function authFetch(path) {
      var nonce = await getNonce();
      if (!nonce) return null;
      var hmac = await computeHmac(nonce);
      return fetch(path, { headers: { 'Authorization': 'send-v1 ' + hmac } });
    }

    async function loadMetadata() {
      var res = await authFetch('/api/metadata/' + fileId);
      if (!res || !res.ok) return null;
      var data = await res.json();
      var metaBytes = sendCrypto.b64Decode(data.metadata);
      try {
        return await sendCrypto.decryptMetadata(secretKey, metaBytes);
      } catch (e) {
        return null;
      }
    }

    async function downloadFile() {
      // The legacy Send service worker intercepts /api/download/{id}. Use the
      // blob alias so returning browsers cannot route this request through the
      // obsolete service-worker download pipeline.
      var res = await authFetch('/api/download/blob/' + fileId);
      if (!res) throw new Error('The download link is no longer available');
      if (!res.ok) throw new Error('Download request failed (HTTP ' + res.status + ')');
      var buf = await res.arrayBuffer();
      try {
        return await sendCrypto.decryptFile(secretKey, new Uint8Array(buf));
      } catch (e) {
        throw new Error('The downloaded file could not be decrypted');
      }
    }

    function showError(msg) {
      var heading = panel.querySelector('h1');
      if (heading) heading.textContent = msg;
      if (downloadBtn) downloadBtn.hidden = true;
      if (passwordForm) passwordForm.hidden = true;
    }

    function showReady() {
      if (downloadBtn) {
        downloadBtn.hidden = false;
        downloadBtn.addEventListener('click', doDownload);
      }
      if (shareUrlInput) shareUrlInput.value = location.href;
      if (qrBtn) qrBtn.hidden = true;
    }

    async function doDownload() {
      if (!downloadBtn) return;
      downloadBtn.disabled = true;
      downloadBtn.textContent = 'Downloading…';

      try {
        var decrypted = await downloadFile();

        var name = metadata ? metadata.name : 'download';
        var type = metadata ? (metadata.type || 'application/octet-stream') : 'application/octet-stream';
        var blob = new Blob([decrypted], { type: type });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = name;
        a.click();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);

        downloadBtn.textContent = 'Download complete';
      } catch (e) {
        console.error(e);
        downloadBtn.disabled = false;
        downloadBtn.textContent = 'Try download again';
        var status = document.getElementById('download-status');
        if (status) status.textContent = e.message || 'Download failed. Please try again.';
      }
    }

    async function prepareDownload() {
      var metaData = await loadMetadata();
      if (!metaData) return false;

      metadata = metaData;
      var heading = panel.querySelector('h1');
      if (heading) heading.textContent = 'Ready to download?';

      var infoEl = document.createElement('p');
      infoEl.className = 'download-info';
      infoEl.textContent = metadata.name + ' (' + formatFileSize(metadata.size || 0) + ')';
      panel.insertBefore(infoEl, downloadBtn || null);
      showReady();
      return true;
    }

    if (passwordForm && window.downloadMetadata && window.downloadMetadata.pwd) {
      passwordForm.addEventListener('submit', async function (event) {
        event.preventDefault();
        passwordBtn.disabled = true;
        passwordError.hidden = true;
        try {
          authentication = await sendCrypto.derivePasswordAuthenticationBytes(passwordInput.value, location.href);
          if (await prepareDownload()) {
            passwordForm.hidden = true;
          } else {
            passwordError.hidden = false;
          }
        } catch (_) {
          passwordError.hidden = false;
        } finally {
          passwordBtn.disabled = false;
        }
      });
      panel.dataset.downloadReady = 'true';
      return;
    }

    var metaData = await prepareDownload();
    if (!metaData) {
      showError('Could not load file information');
      panel.dataset.downloadReady = 'true';
      return;
    }
    panel.dataset.downloadReady = 'true';
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDownloadPage);
  } else {
    initDownloadPage();
  }
})();
