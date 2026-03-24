import type { PublicKey, PrivateKey } from '../types.js';
export interface EncryptedBox {
    ephemeralPublicKey: string;
    nonce: string;
    ciphertext: string;
}
export declare function encryptForPublicKey(plaintext: string, recipientPublicKey: PublicKey): EncryptedBox;
export declare function decryptWithPrivateKey(box: EncryptedBox, recipientPrivateKey: PrivateKey): string;
export declare function serializeEncryptedBox(box: EncryptedBox): string;
export declare function deserializeEncryptedBox(serialized: string): EncryptedBox;
//# sourceMappingURL=ecies.d.ts.map