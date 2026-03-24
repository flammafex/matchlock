export type SigningPublicKey = string;
export type SigningPrivateKey = string;
export type Signature = string;
export declare function generateSigningKeypair(): {
    signingPublicKey: SigningPublicKey;
    signingPrivateKey: SigningPrivateKey;
};
export declare function sign(message: string, signingPrivateKey: SigningPrivateKey): Signature;
export declare function verify(message: string, signature: Signature, signingPublicKey: SigningPublicKey): boolean;
export declare function createSignedRequest(action: string, poolId: string, signingPrivateKey: SigningPrivateKey): {
    signature: Signature;
    timestamp: number;
};
export declare function verifySignedRequest(action: string, poolId: string, signature: Signature, timestamp: number, signingPublicKey: SigningPublicKey, maxAgeMs?: number): boolean;
//# sourceMappingURL=signing.d.ts.map