import { x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
const MATCH_DOMAIN = 'rendezvous-match-v1';
export function generateKeypair() {
    const privateKey = randomBytes(32);
    return {
        publicKey: bytesToHex(x25519.getPublicKey(privateKey)),
        privateKey: bytesToHex(privateKey),
    };
}
export function deriveMatchToken(myPrivateKey, theirPublicKey, poolId) {
    const shared = x25519.scalarMult(hexToBytes(myPrivateKey), hexToBytes(theirPublicKey));
    const encoder = new TextEncoder();
    const input = new Uint8Array([...shared, ...encoder.encode(poolId), ...encoder.encode(MATCH_DOMAIN)]);
    return bytesToHex(sha256(input));
}
export function deriveMatchTokens(myPrivateKey, theirPublicKeys, poolId) {
    return theirPublicKeys.map(pk => deriveMatchToken(myPrivateKey, pk, poolId));
}
//# sourceMappingURL=index.js.map