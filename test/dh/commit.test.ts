import { generateKeypair, deriveMatchToken } from '../../src/dh/index.js';
import { commitToken, commitTokens, verifyCommitment } from '../../src/dh/commit.js';

describe('commit-reveal', () => {
  it('commitment is deterministic', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    expect(commitToken(token)).toBe(commitToken(token));
  });

  it('commitment differs from the token itself', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    expect(commitToken(token)).not.toBe(token);
  });

  it('verifyCommitment accepts correct token', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    expect(verifyCommitment(token, commitToken(token))).toBe(true);
  });

  it('verifyCommitment rejects wrong token', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const carol = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    const wrongToken = deriveMatchToken(alice.privateKey, carol.publicKey, 'pool-1');
    expect(verifyCommitment(wrongToken, commitToken(token))).toBe(false);
  });

  it('commitTokens returns one commitment per token', () => {
    const alice = generateKeypair();
    const others = [generateKeypair(), generateKeypair()];
    const tokens = others.map(k => deriveMatchToken(alice.privateKey, k.publicKey, 'pool-1'));
    const commits = commitTokens(tokens);
    expect(commits).toHaveLength(2);
    commits.forEach(c => expect(c).toMatch(/^[0-9a-f]{64}$/));
  });
});
