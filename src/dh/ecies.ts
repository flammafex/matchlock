import { x25519 } from '@noble/curves/ed25519';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import type { PublicKey, PrivateKey } from '../types.js';

const ENCRYPTION_DOMAIN = 'rendezvous-encrypt-v1';

export interface EncryptedBox {
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
}

export function encryptForPublicKey(plaintext: string, recipientPublicKey: PublicKey): EncryptedBox {
  const ephemeralPrivateKey = randomBytes(32);
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);
  const sharedSecret = x25519.scalarMult(ephemeralPrivateKey, hexToBytes(recipientPublicKey));
  const nonce = randomBytes(24);
  const key = hkdf(sha256, sharedSecret, nonce, new TextEncoder().encode(ENCRYPTION_DOMAIN), 32);
  const ciphertext = xchacha20poly1305(key, nonce).encrypt(new TextEncoder().encode(plaintext));
  return { ephemeralPublicKey: bytesToHex(ephemeralPublicKey), nonce: bytesToHex(nonce), ciphertext: bytesToHex(ciphertext) };
}

export function decryptWithPrivateKey(box: EncryptedBox, recipientPrivateKey: PrivateKey): string {
  const sharedSecret = x25519.scalarMult(hexToBytes(recipientPrivateKey), hexToBytes(box.ephemeralPublicKey));
  const nonce = hexToBytes(box.nonce);
  const key = hkdf(sha256, sharedSecret, nonce, new TextEncoder().encode(ENCRYPTION_DOMAIN), 32);
  return new TextDecoder().decode(xchacha20poly1305(key, nonce).decrypt(hexToBytes(box.ciphertext)));
}

export function serializeEncryptedBox(box: EncryptedBox): string {
  return Buffer.from(JSON.stringify(box)).toString('base64');
}

export function deserializeEncryptedBox(serialized: string): EncryptedBox {
  return JSON.parse(Buffer.from(serialized, 'base64').toString('utf-8')) as EncryptedBox;
}
