import { generateSigningKeypair, sign, verify, createSignedRequest, verifySignedRequest } from '../../src/dh/signing.js';

describe('Ed25519 signing', () => {
  it('sign + verify round-trip', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    expect(verify('hello', sign('hello', signingPrivateKey), signingPublicKey)).toBe(true);
  });

  it('verify rejects wrong message', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    expect(verify('world', sign('hello', signingPrivateKey), signingPublicKey)).toBe(false);
  });

  it('verify rejects wrong key', () => {
    const { signingPrivateKey } = generateSigningKeypair();
    const { signingPublicKey: wrongPub } = generateSigningKeypair();
    expect(verify('hello', sign('hello', signingPrivateKey), wrongPub)).toBe(false);
  });

  it('createSignedRequest + verifySignedRequest round-trip', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    const { signature, timestamp } = createSignedRequest('psi-setup', 'pool-1', signingPrivateKey);
    expect(verifySignedRequest('psi-setup', 'pool-1', signature, timestamp, signingPublicKey)).toBe(true);
  });

  it('verifySignedRequest rejects stale timestamp', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    const staleTimestamp = Date.now() - 10 * 60 * 1000;
    expect(verifySignedRequest('psi-setup', 'pool-1', sign(`psi-setup:pool-1:${staleTimestamp}`, signingPrivateKey), staleTimestamp, signingPublicKey)).toBe(false);
  });
});
