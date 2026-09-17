// crypto.js — all key derivation and encryption happens HERE, in the
// browser. The master password itself is never sent to the server.
//
// From one master password + a per-user salt we derive two
// independent keys (domain-separated so one can never be used to
// reconstruct the other):
//   - authKey  -> sent to the server (as "authProof") only to prove
//                 you know the master password at login/register.
//   - encKey   -> kept in memory only, used to encrypt/decrypt the
//                 vault. Never transmitted anywhere.

const PBKDF2_ITERATIONS = 210000;

function b64encode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function b64decode(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

function randomSaltB64(bytes = 16) {
  return b64encode(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function importPasswordKey(password) {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
}

async function deriveAuthProof(password, saltB64) {
  const baseKey = await importPasswordKey(password);
  const salt = new TextEncoder().encode('auth:' + saltB64);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    256
  );
  return b64encode(bits);
}

async function deriveEncKey(password, saltB64) {
  const baseKey = await importPasswordKey(password);
  const salt = new TextEncoder().encode('enc:' + saltB64);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptVault(vaultObj, encKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const plaintext = enc.encode(JSON.stringify(vaultObj));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encKey, plaintext);
  return { iv: b64encode(iv), blob: b64encode(ciphertext) };
}

async function decryptVault({ iv, blob }, encKey) {
  const ivBytes = b64decode(iv);
  const ciphertext = b64decode(blob);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, encKey, ciphertext);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

window.PassVaultCrypto = {
  randomSaltB64,
  deriveAuthProof,
  deriveEncKey,
  encryptVault,
  decryptVault
};
