// DH primitives
export { generateKeypair, deriveMatchToken, deriveMatchTokens } from './dh/index.js';
export { commitToken, commitTokens, verifyCommitment } from './dh/commit.js';
export { deriveNullifier } from './dh/nullifier.js';
export {
  encryptForPublicKey,
  decryptWithPrivateKey,
  serializeEncryptedBox,
  deserializeEncryptedBox,
} from './dh/ecies.js';
export type { EncryptedBox } from './dh/ecies.js';
export {
  generateSigningKeypair,
  sign,
  verify,
  createSignedRequest,
  verifySignedRequest,
} from './dh/signing.js';
export type { SigningPublicKey, SigningPrivateKey, Signature } from './dh/signing.js';

// Primitive types
export type { MatchToken, CommitHash, PublicKey, PrivateKey } from './types.js';

// PSI
export { PsiService, getPsiService } from './psi/index.js';
export type {
  PsiClientRequest,
  PsiJoinResponse,
  PsiResult,
  OwnerHeldPsiSetup,
  PendingPsiRequest,
  PsiResponseRecord,
  OwnerPsiProcessingResult,
  CreatePsiSetupRequest,
} from './psi/index.js';
