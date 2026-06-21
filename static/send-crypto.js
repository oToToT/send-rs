(function (global) {
  'use strict';

  var ECE_RECORD_SIZE = 64 * 1024;
  var encoder = new TextEncoder();
  var decoder = new TextDecoder();

  function b64Encode(bytes) {
    var binary = '';
    for (var offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode.apply(null, bytes.subarray(offset, offset + 0x8000));
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64Decode(value) {
    value = value.replace(/-/g, '+').replace(/_/g, '/');
    while (value.length % 4) value += '=';
    return Uint8Array.from(atob(value), function (character) {
      return character.charCodeAt(0);
    });
  }

  function concatenate(chunks, length) {
    var result = new Uint8Array(length);
    var offset = 0;
    chunks.forEach(function (chunk) {
      result.set(chunk, offset);
      offset += chunk.length;
    });
    return result;
  }

  async function importHkdf(secret) {
    return crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits', 'deriveKey']);
  }

  async function deriveMetadataKey(secret, usage) {
    var key = await importHkdf(secret);
    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        salt: new Uint8Array(0),
        info: encoder.encode('metadata'),
        hash: 'SHA-256'
      },
      key,
      { name: 'AES-GCM', length: 128 },
      false,
      [usage]
    );
  }

  async function deriveAuthenticationBytes(secret) {
    var key = await importHkdf(secret);
    return new Uint8Array(await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        salt: new Uint8Array(0),
        info: encoder.encode('authentication'),
        hash: 'SHA-256'
      },
      key,
      512
    ));
  }

  async function derivePasswordAuthenticationBytes(password, shareUrl) {
    var passwordKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits']
    );
    return new Uint8Array(await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: encoder.encode(shareUrl),
        iterations: 100,
        hash: 'SHA-256'
      },
      passwordKey,
      512
    ));
  }

  async function signNonce(authenticationBytes, nonce) {
    var key = await crypto.subtle.importKey(
      'raw',
      authenticationBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, nonce));
  }

  async function encryptMetadata(secret, metadata) {
    var key = await deriveMetadataKey(secret, 'encrypt');
    return new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: new Uint8Array(12), tagLength: 128 },
      key,
      encoder.encode(JSON.stringify({
        name: metadata.name,
        size: metadata.size,
        type: metadata.type || 'application/octet-stream',
        manifest: metadata.manifest || {}
      }))
    ));
  }

  async function decryptMetadata(secret, ciphertext) {
    var key = await deriveMetadataKey(secret, 'decrypt');
    var plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(12), tagLength: 128 },
      key,
      ciphertext
    );
    return JSON.parse(decoder.decode(plaintext));
  }

  async function deriveEceMaterial(secret, salt) {
    var input = await importHkdf(secret);
    var key = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        salt: salt,
        info: encoder.encode('Content-Encoding: aes128gcm\0'),
        hash: 'SHA-256'
      },
      input,
      { name: 'AES-GCM', length: 128 },
      false,
      ['encrypt', 'decrypt']
    );
    var nonceBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        salt: salt,
        info: encoder.encode('Content-Encoding: nonce\0'),
        hash: 'SHA-256'
      },
      input,
      128
    );
    return { key: key, nonce: new Uint8Array(nonceBits).slice(0, 12) };
  }

  function recordNonce(base, sequence) {
    if (sequence > 0xffffffff) throw new Error('record sequence number exceeds limit');
    var nonce = base.slice();
    var view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
    view.setUint32(8, (view.getUint32(8) ^ sequence) >>> 0);
    return nonce;
  }

  async function encryptEce(secret, data) {
    data = new Uint8Array(data);
    var salt = crypto.getRandomValues(new Uint8Array(16));
    var material = await deriveEceMaterial(secret, salt);
    var header = new Uint8Array(21);
    header.set(salt);
    var headerView = new DataView(header.buffer);
    headerView.setUint32(16, ECE_RECORD_SIZE);
    header[20] = 0;

    if (data.length === 0) return header;

    var plainRecordSize = ECE_RECORD_SIZE - 17;
    var chunks = [header];
    var total = header.length;
    var sequence = 0;
    for (var offset = 0; offset < data.length; offset += plainRecordSize) {
      var end = Math.min(offset + plainRecordSize, data.length);
      var finalRecord = end === data.length;
      var source = data.subarray(offset, end);
      var paddedLength = finalRecord ? source.length + 1 : ECE_RECORD_SIZE - 16;
      var padded = new Uint8Array(paddedLength);
      padded.set(source);
      padded[source.length] = finalRecord ? 2 : 1;
      var encrypted = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: recordNonce(material.nonce, sequence) },
        material.key,
        padded
      ));
      chunks.push(encrypted);
      total += encrypted.length;
      sequence++;
    }
    return concatenate(chunks, total);
  }

  async function decryptEce(secret, data) {
    data = new Uint8Array(data);
    if (data.length < 21) throw new Error('encrypted file header is incomplete');
    var salt = data.slice(0, 16);
    var view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    var recordSize = view.getUint32(16);
    var idLength = data[20];
    var headerLength = 21 + idLength;
    if (recordSize < 18 || headerLength > data.length) throw new Error('invalid encrypted file header');
    if (headerLength === data.length) return new Uint8Array(0);

    var material = await deriveEceMaterial(secret, salt);
    var chunks = [];
    var total = 0;
    var sequence = 0;
    for (var offset = headerLength; offset < data.length; offset += recordSize) {
      var end = Math.min(offset + recordSize, data.length);
      var finalRecord = end === data.length;
      var ciphertext = data.subarray(offset, end);
      if (ciphertext.length < 17) throw new Error('encrypted file record is incomplete');
      var plaintext = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: recordNonce(material.nonce, sequence), tagLength: 128 },
        material.key,
        ciphertext
      ));
      var delimiter = plaintext.length - 1;
      while (delimiter >= 0 && plaintext[delimiter] === 0) delimiter--;
      var expected = finalRecord ? 2 : 1;
      if (delimiter < 0 || plaintext[delimiter] !== expected) {
        throw new Error('invalid encrypted file record delimiter');
      }
      var chunk = plaintext.slice(0, delimiter);
      chunks.push(chunk);
      total += chunk.length;
      sequence++;
    }
    return concatenate(chunks, total);
  }

  global.SendCrypto = {
    b64Encode: b64Encode,
    b64Decode: b64Decode,
    deriveAuthenticationBytes: deriveAuthenticationBytes,
    derivePasswordAuthenticationBytes: derivePasswordAuthenticationBytes,
    signNonce: signNonce,
    encryptMetadata: encryptMetadata,
    decryptMetadata: decryptMetadata,
    encryptFile: encryptEce,
    decryptFile: decryptEce
  };
})(window);
