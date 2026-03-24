import { x25519 } from '@noble/curves/ed25519';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
const ENCRYPTION_DOMAIN = 'rendezvous-encrypt-v1';
export function encryptForPublicKey(plaintext, recipientPublicKey) {
    const ephemeralPrivateKey = randomBytes(32);
    const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);
    const sharedSecret = x25519.scalarMult(ephemeralPrivateKey, hexToBytes(recipientPublicKey));
    const nonce = randomBytes(24);
    const key = hkdf(sha256, sharedSecret, nonce, new TextEncoder().encode(ENCRYPTION_DOMAIN), 32);
    const ciphertext = xchacha20poly1305(key, nonce).encrypt(new TextEncoder().encode(plaintext));
    return { ephemeralPublicKey: bytesToHex(ephemeralPublicKey), nonce: bytesToHex(nonce), ciphertext: bytesToHex(ciphertext) };
}
export function decryptWithPrivateKey(box, recipientPrivateKey) {
    const sharedSecret = x25519.scalarMult(hexToBytes(recipientPrivateKey), hexToBytes(box.ephemeralPublicKey));
    const nonce = hexToBytes(box.nonce);
    const key = hkdf(sha256, sharedSecret, nonce, new TextEncoder().encode(ENCRYPTION_DOMAIN), 32);
    return new TextDecoder().decode(xchacha20poly1305(key, nonce).decrypt(hexToBytes(box.ciphertext)));
}
export function serializeEncryptedBox(box) {
    return Buffer.from(JSON.stringify(box)).toString('base64');
}
export function deserializeEncryptedBox(serialized) {
    return JSON.parse(Buffer.from(serialized, 'base64').toString('utf-8'));
}
//# sourceMappingURL=ecies.js.map