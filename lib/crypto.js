'use strict';
// Application-level field encryption + blind index.
//
//  - encrypt/decrypt: AES-256-GCM with a fresh random 96-bit IV per call.
//    Packed layout (base64):  [version:1][iv:12][tag:16][ciphertext:...]
//    Optional AAD binds a ciphertext to a context string (e.g. a field name),
//    so a ciphertext cannot be silently moved to a different field/record.
//  - blindIndex: HMAC-SHA256(indexKey, value) → base64. Deterministic, so
//    encrypted fields remain searchable by equality WITHOUT storing plaintext.
//
// SECURITY NOTES
//  - A 96-bit random IV per encryption is the AES-GCM standard; reuse would be
//    catastrophic, so the IV is ALWAYS freshly generated here and never caller-
//    supplied. (Birthday bound: safe well past this app's write volume.)
//  - blindIndex leaks equality: two records with the same value share an index.
//    Only apply it to high-cardinality fields (email, IP). Never to low-
//    cardinality fields (role, boolean flags) — that would leak the value.

const crypto = require('crypto');

const VERSION = 1;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

function createFieldCrypto(encKey, indexKey) {
  if (!Buffer.isBuffer(encKey) || encKey.length !== KEY_LEN) {
    throw new Error(`field encryption key must be ${KEY_LEN} bytes`);
  }
  if (!Buffer.isBuffer(indexKey) || indexKey.length !== KEY_LEN) {
    throw new Error(`blind index key must be ${KEY_LEN} bytes`);
  }

  function encrypt(plaintext, aad) {
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
    if (aad != null) cipher.setAAD(Buffer.from(String(aad), 'utf8'));
    const pt = Buffer.from(String(plaintext), 'utf8');
    const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([Buffer.from([VERSION]), iv, tag, ct]).toString('base64');
  }

  function decrypt(packed, aad) {
    const buf = Buffer.from(String(packed), 'base64');
    if (buf.length < 1 + IV_LEN + TAG_LEN) throw new Error('ciphertext too short');
    if (buf[0] !== VERSION) throw new Error('unsupported ciphertext version');
    const iv = buf.subarray(1, 1 + IV_LEN);
    const tag = buf.subarray(1 + IV_LEN, 1 + IV_LEN + TAG_LEN);
    const ct = buf.subarray(1 + IV_LEN + TAG_LEN);
    const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, iv);
    if (aad != null) decipher.setAAD(Buffer.from(String(aad), 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  }

  function blindIndex(value) {
    return crypto.createHmac('sha256', indexKey).update(String(value), 'utf8').digest('base64');
  }

  return { encrypt, decrypt, blindIndex };
}

module.exports = { createFieldCrypto };
