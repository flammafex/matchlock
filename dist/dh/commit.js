import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
export function commitToken(matchToken) {
    // Hash the 32 raw bytes, not the 64-char hex encoding
    return bytesToHex(sha256(hexToBytes(matchToken)));
}
export function commitTokens(matchTokens) {
    return matchTokens.map(commitToken);
}
export function verifyCommitment(matchToken, commitHash) {
    const computed = commitToken(matchToken);
    if (computed.length !== commitHash.length)
        return false;
    let result = 0;
    for (let i = 0; i < computed.length; i++) {
        result |= computed.charCodeAt(i) ^ commitHash.charCodeAt(i);
    }
    return result === 0;
}
//# sourceMappingURL=commit.js.map