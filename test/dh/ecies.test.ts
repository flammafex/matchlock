import { generateKeypair } from '../../src/dh/index.js';
import { encryptForPublicKey, decryptWithPrivateKey, serializeEncryptedBox, deserializeEncryptedBox } from '../../src/dh/ecies.js';

describe('ECIES', () => {
  it('encrypts and decrypts round-trip', () => {
    const { publicKey, privateKey } = generateKeypair();
    expect(decryptWithPrivateKey(encryptForPublicKey('hello matchlock', publicKey), privateKey)).toBe('hello matchlock');
  });

  it('produces different ciphertext each call', () => {
    const { publicKey } = generateKeypair();
    const box1 = encryptForPublicKey('same', publicKey);
    const box2 = encryptForPublicKey('same', publicKey);
    expect(box1.ciphertext).not.toBe(box2.ciphertext);
  });

  it('throws on tampered ciphertext', () => {
    const { publicKey, privateKey } = generateKeypair();
    const box = encryptForPublicKey('secret', publicKey);
    const tampered = { ...box, ciphertext: box.ciphertext.slice(0, -2) + (box.ciphertext.slice(-2) === 'ff' ? '00' : 'ff') };
    expect(() => decryptWithPrivateKey(tampered, privateKey)).toThrow();
  });

  it('throws with wrong private key', () => {
    const { publicKey } = generateKeypair();
    const { privateKey: wrongKey } = generateKeypair();
    expect(() => decryptWithPrivateKey(encryptForPublicKey('secret', publicKey), wrongKey)).toThrow();
  });

  it('serialize/deserialize round-trip', () => {
    const { publicKey, privateKey } = generateKeypair();
    const box = encryptForPublicKey('serialize me', publicKey);
    expect(decryptWithPrivateKey(deserializeEncryptedBox(serializeEncryptedBox(box)), privateKey)).toBe('serialize me');
  });
});
