// Crypto module — overrides fetchJSON with AES-256-CBC encryption when __BUILD.encrypted is set.
// Key is SHA-256 of the password, stored in sessionStorage by the login page script.
(function() {
  if (!__BUILD.encrypted) return;

  let encKeyHex = sessionStorage.getItem('__enc_key');
  if (!encKeyHex) {
    const pw = prompt('Enter encryption passphrase (same as login password):');
    if (!pw) return;
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw)).then(h => {
      const hex = Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
      sessionStorage.setItem('__enc_key', hex);
      location.reload();
    });
    return;
  }

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    return bytes;
  }

  function getKey() {
    return crypto.subtle.importKey('raw', hexToBytes(encKeyHex), { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
  }

  async function encryptStr(plaintext) {
    const key = await getKey();
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const enc = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, new TextEncoder().encode(plaintext));
    const buf = new Uint8Array(16 + enc.byteLength);
    buf.set(iv);
    buf.set(new Uint8Array(enc), 16);
    // Manual base64 encode to handle large payloads without stack overflow
    let binary = '';
    for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]);
    return btoa(binary);
  }

  async function decryptStr(b64) {
    const key = await getKey();
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const iv = raw.slice(0, 16);
    const ct = raw.slice(16);
    const dec = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, ct);
    return new TextDecoder().decode(dec);
  }

  // Override fetchJSON for transparent encryption
  window.fetchJSON = async function(fd) {
    // Skip encryption for file uploads
    for (const [, v] of fd.entries()) {
      if (v instanceof File) {
        return fetch(BASE_URL, { method: 'POST', body: fd })
          .then(r => r.text())
          .then(text => {
            try { return JSON.parse(text); }
            catch(e) { throw new Error('PHP returned non-JSON:\n' + text.substring(0, 500)); }
          });
      }
    }

    const params = new URLSearchParams(fd).toString();
    const encPayload = await encryptStr(params);
    const encFd = new FormData();
    encFd.append('__enc', encPayload);

    const response = await fetch(BASE_URL, { method: 'POST', body: encFd });
    const encText = await response.text();
    try {
      const plaintext = await decryptStr(encText);
      return JSON.parse(plaintext);
    } catch(e) {
      try { return JSON.parse(encText); }
      catch(e2) { throw new Error('Decryption/parse failed:\n' + encText.substring(0, 500)); }
    }
  };
})();
