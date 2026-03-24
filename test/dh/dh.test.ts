import { generateKeypair, deriveMatchToken, deriveMatchTokens } from '../../src/dh/index.js';

describe('DH token derivation', () => {
  it('mutual selection produces equal tokens', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const poolId = 'pool-1';
    const aliceToken = deriveMatchToken(alice.privateKey, bob.publicKey, poolId);
    const bobToken = deriveMatchToken(bob.privateKey, alice.publicKey, poolId);
    expect(aliceToken).toBe(bobToken);
  });

  it('unilateral selection produces different tokens', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const carol = generateKeypair();
    const aliceSelectsBob = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    const bobSelectsCarol = deriveMatchToken(bob.privateKey, carol.publicKey, 'pool-1');
    expect(aliceSelectsBob).not.toBe(bobSelectsCarol);
  });

  it('tokens are pool-scoped', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const token1 = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-a');
    const token2 = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-b');
    expect(token1).not.toBe(token2);
  });

  it('deriveMatchTokens returns one token per public key', () => {
    const alice = generateKeypair();
    const others = [generateKeypair(), generateKeypair(), generateKeypair()];
    const tokens = deriveMatchTokens(alice.privateKey, others.map(k => k.publicKey), 'pool-1');
    expect(tokens).toHaveLength(3);
    tokens.forEach(t => expect(t).toMatch(/^[0-9a-f]{64}$/));
  });

  it('tokens are 64-char hex strings', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    expect(deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1')).toMatch(/^[0-9a-f]{64}$/);
  });
});
