(function () {
  'use strict';

  function b64Encode(bytes) {
    return btoa(String.fromCharCode.apply(null, bytes))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64Decode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return Uint8Array.from(atob(str), function (c) { return c.charCodeAt(0); });
  }

  function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = 0;
    var size = bytes;
    while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
    return i === 0 ? bytes + ' ' + units[i] : size.toFixed(1) + ' ' + units[i];
  }

  async function deriveAesKey(secretKey) {
    var hkdfKey = await crypto.subtle.importKey('raw', secretKey, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', salt: new Uint8Array(0), info: new TextEncoder().encode('send-encryption'), hash: 'SHA-256' },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  async function deriveHmacKey(secretKey) {
    return crypto.subtle.importKey('raw', secretKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  }

  function decryptData(aesKey, data) {
    var iv = data.slice(0, 12);
    var ciphertext = data.slice(12);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, aesKey, ciphertext);
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

    var secretKey = b64Decode(keyB64);
    var aesKey = null;
    var metadata = null;
    var hmacKey = null;

    try {
      aesKey = await deriveAesKey(secretKey);
      hmacKey = await deriveHmacKey(secretKey);
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
      var nonce = b64Decode(nonceB64);
      var sig = await crypto.subtle.sign('HMAC', hmacKey, nonce);
      return b64Encode(new Uint8Array(sig));
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
      var metaBytes = b64Decode(data.metadata);
      try {
        var decrypted = await decryptData(aesKey, metaBytes);
        var text = new TextDecoder().decode(decrypted);
        return JSON.parse(text);
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
        return await decryptData(aesKey, new Uint8Array(buf));
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

    var metaData = await loadMetadata();
    if (!metaData) {
      showError('Could not load file information');
      panel.dataset.downloadReady = 'true';
      return;
    }

    metadata = metaData;

    var heading = panel.querySelector('h1');
    if (heading) heading.textContent = 'Ready to download?';

    var infoEl = document.createElement('p');
    infoEl.className = 'download-info';
    infoEl.textContent = metadata.name + ' (' + formatFileSize(metadata.size || 0) + ')';
    panel.insertBefore(infoEl, downloadBtn || null);

    showReady();
    panel.dataset.downloadReady = 'true';
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDownloadPage);
  } else {
    initDownloadPage();
  }
})();
