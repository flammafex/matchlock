import { x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import type { MatchToken, PublicKey, PrivateKey } from '../types.js';

const MATCH_DOMAIN = 'rendezvous-match-v1';

export function generateKeypair(): { publicKey: PublicKey; privateKey: PrivateKey } {
  const privateKey = randomBytes(32);
  return {
    publicKey: bytesToHex(x25519.getPublicKey(privateKey)),
    privateKey: bytesToHex(privateKey),
  };
}

export function deriveMatchToken(myPrivateKey: PrivateKey, theirPublicKey: PublicKey, poolId: string): MatchToken {
  const shared = x25519.scalarMult(hexToBytes(myPrivateKey), hexToBytes(theirPublicKey));
  const encoder = new TextEncoder();
  const input = new Uint8Array([...shared, ...encoder.encode(poolId), ...encoder.encode(MATCH_DOMAIN)]);
  return bytesToHex(sha256(input));
}

export function deriveMatchTokens(myPrivateKey: PrivateKey, theirPublicKeys: PublicKey[], poolId: string): MatchToken[] {
  return theirPublicKeys.map(pk => deriveMatchToken(myPrivateKey, pk, poolId));
}
