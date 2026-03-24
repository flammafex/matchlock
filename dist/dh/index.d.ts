import type { MatchToken, PublicKey, PrivateKey } from '../types.js';
export declare function generateKeypair(): {
    publicKey: PublicKey;
    privateKey: PrivateKey;
};
export declare function deriveMatchToken(myPrivateKey: PrivateKey, theirPublicKey: PublicKey, poolId: string): MatchToken;
export declare function deriveMatchTokens(myPrivateKey: PrivateKey, theirPublicKeys: PublicKey[], poolId: string): MatchToken[];
//# sourceMappingURL=index.d.ts.map