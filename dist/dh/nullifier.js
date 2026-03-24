import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
const NULLIFIER_DOMAIN = 'rendezvous-nullifier-v1';
export function deriveNullifier(privateKey, poolId) {
    const encoder = new TextEncoder();
    const input = new Uint8Array([...hexToBytes(privateKey), ...encoder.encode(poolId), ...encoder.encode(NULLIFIER_DOMAIN)]);
    return bytesToHex(sha256(input));
}
//# sourceMappingURL=nullifier.js.map