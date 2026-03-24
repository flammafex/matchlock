import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import type { MatchToken, CommitHash } from '../types.js';

export function commitToken(matchToken: MatchToken): CommitHash {
  return bytesToHex(sha256(new TextEncoder().encode(matchToken)));
}

export function commitTokens(matchTokens: MatchToken[]): CommitHash[] {
  return matchTokens.map(commitToken);
}

export function verifyCommitment(matchToken: MatchToken, commitHash: CommitHash): boolean {
  const computed = commitToken(matchToken);
  if (computed.length !== commitHash.length) return false;
  let result = 0;
  for (let i = 0; i < computed.length; i++) {
    result |= computed.charCodeAt(i) ^ commitHash.charCodeAt(i);
  }
  return result === 0;
}
