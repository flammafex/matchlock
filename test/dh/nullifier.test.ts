import { generateKeypair } from '../../src/dh/index.js';
import { deriveNullifier } from '../../src/dh/nullifier.js';

describe('nullifier', () => {
  it('same key + same pool = same nullifier', () => {
    const { privateKey } = generateKeypair();
    expect(deriveNullifier(privateKey, 'pool-1')).toBe(deriveNullifier(privateKey, 'pool-1'));
  });

  it('same key + different pool = different nullifier', () => {
    const { privateKey } = generateKeypair();
    expect(deriveNullifier(privateKey, 'pool-1')).not.toBe(deriveNullifier(privateKey, 'pool-2'));
  });

  it('different keys + same pool = different nullifier', () => {
    const a = generateKeypair();
    const b = generateKeypair();
    expect(deriveNullifier(a.privateKey, 'pool-1')).not.toBe(deriveNullifier(b.privateKey, 'pool-1'));
  });

  it('nullifier is 64-char hex', () => {
    const { privateKey } = generateKeypair();
    expect(deriveNullifier(privateKey, 'pool-1')).toMatch(/^[0-9a-f]{64}$/);
  });
});
