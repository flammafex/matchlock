import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
const SIGNING_DOMAIN = 'rendezvous-sign-v1';
export function generateSigningKeypair() {
    const privateKey = ed25519.utils.randomPrivateKey();
    return { signingPublicKey: bytesToHex(ed25519.getPublicKey(privateKey)), signingPrivateKey: bytesToHex(privateKey) };
}
export function sign(message, signingPrivateKey) {
    const encoder = new TextEncoder();
    const messageHash = sha256(new Uint8Array([...encoder.encode(SIGNING_DOMAIN), ...encoder.encode(message)]));
    return bytesToHex(ed25519.sign(messageHash, hexToBytes(signingPrivateKey)));
}
export function verify(message, signature, signingPublicKey) {
    try {
        const encoder = new TextEncoder();
        const messageHash = sha256(new Uint8Array([...encoder.encode(SIGNING_DOMAIN), ...encoder.encode(message)]));
        return ed25519.verify(hexToBytes(signature), messageHash, hexToBytes(signingPublicKey));
    }
    catch {
        return false;
    }
}
export function createSignedRequest(action, poolId, signingPrivateKey) {
    const timestamp = Date.now();
    return { signature: sign(`${action}:${poolId}:${timestamp}`, signingPrivateKey), timestamp };
}
export function verifySignedRequest(action, poolId, signature, timestamp, signingPublicKey, maxAgeMs = 5 * 60 * 1000) {
    if (Math.abs(Date.now() - timestamp) > maxAgeMs)
        return false;
    return verify(`${action}:${poolId}:${timestamp}`, signature, signingPublicKey);
}
//# sourceMappingURL=signing.js.map