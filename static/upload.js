(function () {
  'use strict';

  function b64Encode(bytes) {
    return btoa(String.fromCharCode.apply(null, bytes))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
      ['encrypt']
    );
  }

  async function encryptMetadata(aesKey, name, type, size) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var plaintext = new TextEncoder().encode(JSON.stringify({ name: name, type: type, size: size }));
    var ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, plaintext);
    var combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);
    return b64Encode(combined);
  }

  async function encryptFile(aesKey, file) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var fileData = await file.arrayBuffer();
    var ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, fileData);
    var combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);
    return combined;
  }

  function initUploadPage() {
    var root = document.querySelector('.fallback-main');
    if (!root || root.dataset.uploadReady === 'true') return;

    var picker = root.querySelector('.file-picker');
    var pickerStrong = picker ? picker.querySelector('strong') : null;
    var fileInput = root.querySelector('#file-upload');
    var fileStatus = root.querySelector('#file-selection-status');
    var fileList = root.querySelector('#file-list');
    var uploadBtn = root.querySelector('#upload-btn');
    var passwordToggle = root.querySelector('#add-password');
    var passwordRow = root.querySelector('.input-action');
    var passwordInput = root.querySelector('#password-input');
    var previewButton = root.querySelector('#password-preview-button');
    var dlCount = root.querySelector('#dlCount');
    var timespan = root.querySelector('#timespan');

    var selectedFiles = [];

    function renderFileList() {
      if (!fileList || !fileStatus) return;
      fileList.innerHTML = '';
      var totalBytes = 0;
      selectedFiles.forEach(function (file, index) {
        totalBytes += file.size;
        var li = document.createElement('li');
        li.className = 'file-list-item';
        li.innerHTML =
          '<svg class="file-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>' +
          '<span class="file-name" title="' + file.name.replace(/"/g, '&quot;') + '">' + file.name.replace(/</g, '&lt;') + '</span>' +
          '<span class="file-size">' + formatFileSize(file.size) + '</span>' +
          '<button class="remove-file" type="button" aria-label="Remove ' + file.name.replace(/"/g, '&quot;') + '">&times;</button>';
        li.querySelector('.remove-file').addEventListener('click', function () {
          selectedFiles.splice(index, 1);
          renderFileList();
        });
        fileList.appendChild(li);
      });
      var count = selectedFiles.length;
      if (count === 0) {
        fileList.hidden = true;
        fileStatus.textContent = 'No files selected';
        if (picker) picker.classList.remove('has-files');
        if (pickerStrong) pickerStrong.textContent = 'Drop files here';
        if (uploadBtn) uploadBtn.disabled = true;
      } else {
        fileList.hidden = false;
        var label = count === 1 ? '1 file selected' : count + ' files selected';
        fileStatus.textContent = label + (totalBytes ? ' (' + formatFileSize(totalBytes) + ' total)' : '');
        if (picker) picker.classList.add('has-files');
        if (pickerStrong) pickerStrong.textContent = 'Add more files';
        if (uploadBtn) uploadBtn.disabled = false;
      }
    }

    function addFiles(newFiles) {
      for (var i = 0; i < newFiles.length; i++) {
        var duplicate = false;
        for (var j = 0; j < selectedFiles.length; j++) {
          if (selectedFiles[j].name === newFiles[i].name && selectedFiles[j].size === newFiles[i].size) {
            duplicate = true;
            break;
          }
        }
        if (!duplicate) selectedFiles.push(newFiles[i]);
      }
      renderFileList();
    }

    if (picker && fileInput) {
      fileInput.addEventListener('change', function () {
        if (fileInput.files) addFiles(fileInput.files);
        fileInput.value = '';
      });

      picker.addEventListener('dragover', function (e) {
        e.preventDefault();
      });
      picker.addEventListener('dragenter', function () {
        picker.classList.add('is-dragging');
      });
      picker.addEventListener('dragleave', function () {
        picker.classList.remove('is-dragging');
      });
      picker.addEventListener('drop', function (e) {
        e.preventDefault();
        picker.classList.remove('is-dragging');
        if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files);
      });
    }

    if (passwordToggle && passwordRow && passwordInput) {
      passwordToggle.addEventListener('change', function () {
        passwordRow.hidden = !passwordToggle.checked;
        if (passwordToggle.checked) passwordInput.focus();
        else { passwordInput.value = ''; passwordInput.type = 'password'; }
      });
    }

    if (previewButton && passwordInput) {
      previewButton.addEventListener('click', function () {
        var showing = passwordInput.type === 'text';
        passwordInput.type = showing ? 'password' : 'text';
        previewButton.textContent = showing ? 'Show' : 'Hide';
        previewButton.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
        previewButton.setAttribute('aria-pressed', String(!showing));
        passwordInput.focus();
      });
    }

    if (uploadBtn) {
      uploadBtn.addEventListener('click', startUpload);
    }

    async function startUpload() {
      if (selectedFiles.length === 0) return;
      uploadBtn.disabled = true;
      uploadBtn.textContent = 'Encrypting and uploading…';

      var prevResult = root.querySelector('.upload-result');
      if (prevResult) prevResult.remove();
      var prevError = root.querySelector('.upload-error');
      if (prevError) prevError.remove();

      try {
        var secretKey = crypto.getRandomValues(new Uint8Array(32));
        var aesKey = await deriveAesKey(secretKey);
        var file = selectedFiles[0];

        uploadBtn.textContent = 'Encrypting…';
        var fileMetadata = await encryptMetadata(aesKey, file.name, file.type || 'application/octet-stream', file.size);
        var encryptedFile = await encryptFile(aesKey, file);

        var protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        var wsUrl = protocol + '//' + location.host + '/api/ws';

        uploadBtn.textContent = 'Uploading…';
        var result = await new Promise(function (resolve, reject) {
          var ws = new WebSocket(wsUrl);
          ws.binaryType = 'arraybuffer';
          var shareUrl = null;
          var timeout = setTimeout(function () {
            ws.close();
            reject(new Error('Upload timed out'));
          }, 120000);

          ws.onopen = function () {
            ws.send(JSON.stringify({
              fileMetadata: fileMetadata,
              authorization: 'send-v1 ' + b64Encode(secretKey),
              timeLimit: parseInt(timespan ? timespan.value : 86400, 10),
              dlimit: parseInt(dlCount ? dlCount.value : 1, 10)
            }));
          };

          ws.onmessage = function (event) {
            if (typeof event.data !== 'string') return;
            try {
              var msg = JSON.parse(event.data);
              if (msg.url) {
                shareUrl = msg.url + '#' + b64Encode(secretKey);
                ws.send(encryptedFile);
                ws.send(new Uint8Array([0]));
              } else if (msg.ok === true) {
                clearTimeout(timeout);
                ws.close();
                resolve(shareUrl);
              } else if (msg.error) {
                clearTimeout(timeout);
                ws.close();
                reject(new Error(msg.error === 413 ? 'File too large' : 'Upload failed (error ' + msg.error + ')'));
              }
            } catch (e) {
              clearTimeout(timeout);
              reject(e);
            }
          };

          ws.onerror = function () { clearTimeout(timeout); reject(new Error('Connection failed')); };
          ws.onclose = function () { clearTimeout(timeout); reject(new Error('Connection closed')); };
        });

        selectedFiles = [];
        renderFileList();
        uploadBtn.textContent = 'Create secure link';

        var linkEl = document.createElement('div');
        linkEl.className = 'upload-result';
        linkEl.innerHTML =
          '<p class="upload-result-label">Your secure share link is ready</p>' +
          '<div class="upload-result-row">' +
          '<input id="share-url" class="upload-result-input" type="text" readonly aria-label="Secure share link">' +
          '<button id="copy-btn" class="upload-result-copy" type="button">Copy</button>' +
          '<a id="open-link" class="upload-result-open" target="_blank" rel="noopener">Open link</a></div>';
        uploadBtn.parentNode.insertBefore(linkEl, uploadBtn.nextSibling);

        var shareInput = document.getElementById('share-url');
        var openLink = document.getElementById('open-link');
        shareInput.value = result;
        openLink.href = result;

        document.getElementById('copy-btn').addEventListener('click', function () {
          var self = this;
          var copied = navigator.clipboard && window.isSecureContext
            ? navigator.clipboard.writeText(shareInput.value)
            : new Promise(function (resolve) {
                shareInput.select();
                document.execCommand('copy');
                resolve();
              });
          copied.then(function () {
            self.textContent = 'Copied!';
            setTimeout(function () { self.textContent = 'Copy'; }, 2000);
          });
        });



      } catch (err) {
        uploadBtn.textContent = 'Create secure link';
        uploadBtn.disabled = false;
        var errEl = document.createElement('p');
        errEl.className = 'upload-error';
        errEl.textContent = 'Upload failed: ' + err.message;
        uploadBtn.parentNode.insertBefore(errEl, uploadBtn.nextSibling);
        setTimeout(function () { errEl.remove(); }, 5000);
      }
    }

    root.dataset.uploadReady = 'true';
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initUploadPage);
  } else {
    initUploadPage();
  }
})();
