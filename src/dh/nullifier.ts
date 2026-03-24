import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import type { PrivateKey } from '../types.js';

const NULLIFIER_DOMAIN = 'rendezvous-nullifier-v1';

export function deriveNullifier(privateKey: PrivateKey, poolId: string): string {
  const encoder = new TextEncoder();
  const input = new Uint8Array([...hexToBytes(privateKey), ...encoder.encode(poolId), ...encoder.encode(NULLIFIER_DOMAIN)]);
  return bytesToHex(sha256(input));
}
