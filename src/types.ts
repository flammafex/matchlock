/** Hex-encoded X25519 public key (64 chars) */
export type PublicKey = string & { readonly __brand: 'PublicKey' };

/** Hex-encoded X25519 private key (64 chars) */
export type PrivateKey = string & { readonly __brand: 'PrivateKey' };

/** Hex-encoded match token — SHA-256 of DH shared secret (64 chars) */
export type MatchToken = string & { readonly __brand: 'MatchToken' };

/** Hex-encoded commitment hash — SHA-256 of a MatchToken (64 chars) */
export type CommitHash = string & { readonly __brand: 'CommitHash' };

/** Hex-encoded nullifier — SHA-256 of private key + pool ID + domain (64 chars) */
export type Nullifier = string & { readonly __brand: 'Nullifier' };

const HEX_64 = /^[0-9a-f]{64}$/;

export function isValidPublicKey(hex: string): hex is PublicKey {
  return HEX_64.test(hex);
}

export function isValidPrivateKey(hex: string): hex is PrivateKey {
  return HEX_64.test(hex);
}
