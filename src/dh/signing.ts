import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const SIGNING_DOMAIN = 'rendezvous-sign-v1';

export type SigningPublicKey = string;
export type SigningPrivateKey = string;
export type Signature = string;

export function generateSigningKeypair(): { signingPublicKey: SigningPublicKey; signingPrivateKey: SigningPrivateKey } {
  const privateKey = ed25519.utils.randomPrivateKey();
  return { signingPublicKey: bytesToHex(ed25519.getPublicKey(privateKey)), signingPrivateKey: bytesToHex(privateKey) };
}

export function sign(message: string, signingPrivateKey: SigningPrivateKey): Signature {
  const encoder = new TextEncoder();
  const messageHash = sha256(new Uint8Array([...encoder.encode(SIGNING_DOMAIN), ...encoder.encode(message)]));
  return bytesToHex(ed25519.sign(messageHash, hexToBytes(signingPrivateKey)));
}

export function verify(message: string, signature: Signature, signingPublicKey: SigningPublicKey): boolean {
  try {
    const encoder = new TextEncoder();
    const messageHash = sha256(new Uint8Array([...encoder.encode(SIGNING_DOMAIN), ...encoder.encode(message)]));
    return ed25519.verify(hexToBytes(signature), messageHash, hexToBytes(signingPublicKey));
  } catch { return false; }
}

export function createSignedRequest(action: string, poolId: string, signingPrivateKey: SigningPrivateKey): { signature: Signature; timestamp: number } {
  const timestamp = Date.now();
  return { signature: sign(`${action}:${poolId}:${timestamp}`, signingPrivateKey), timestamp };
}

export function verifySignedRequest(action: string, poolId: string, signature: Signature, timestamp: number, signingPublicKey: SigningPublicKey, maxAgeMs = 5 * 60 * 1000): boolean {
  if (Math.abs(Date.now() - timestamp) > maxAgeMs) return false;
  return verify(`${action}:${poolId}:${timestamp}`, signature, signingPublicKey);
}
