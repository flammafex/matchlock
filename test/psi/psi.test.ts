import { generateKeypair } from '../../src/dh/index.js';
import { decryptWithPrivateKey, deserializeEncryptedBox } from '../../src/dh/ecies.js';
import { PsiService } from '../../src/psi/service.js';

describe('PsiService — owner-held key flow', () => {
  let psi: PsiService;

  beforeAll(async () => {
    psi = new PsiService();
    await psi.init();
  }, 60000);

  it('full owner-held key round-trip: setup → request → process → intersect', async () => {
    const ownerKeypair = generateKeypair();
    const ownerTokens = ['token-alice-bob', 'token-alice-carol', 'token-alice-dave'];

    const setup = await psi.createOwnerEncryptedSetup(
      { poolId: 'test-pool', matchTokens: ownerTokens },
      ownerKeypair.publicKey,
    );

    expect(setup.encryptedServerKey).toBeTruthy();
    expect(setup.setupMessage).toBeTruthy();
    expect(setup.ownerPublicKey).toBe(ownerKeypair.publicKey);

    const joinerTokens = ['token-alice-bob', 'token-joiner-eve']; // one overlap
    const { request: psiRequest, clientKey } = await psi.createRequest(joinerTokens);

    const box = deserializeEncryptedBox(setup.encryptedServerKey);
    const decryptedServerKey = decryptWithPrivateKey(box, ownerKeypair.privateKey);
    const psiResponse = await psi.processRequestWithDecryptedKey(decryptedServerKey, psiRequest);

    const result = await psi.computeIntersection(clientKey, joinerTokens, setup.setupMessage, psiResponse);

    expect(result.intersection).toContain('token-alice-bob');
    expect(result.cardinality).toBe(1);
  }, 60000);

  it('cardinality-only mode', async () => {
    const ownerKeypair = generateKeypair();
    const setup = await psi.createOwnerEncryptedSetup(
      { poolId: 'test-pool-2', matchTokens: ['a', 'b', 'c'] },
      ownerKeypair.publicKey,
    );

    const { request, clientKey } = await psi.createRequest(['a', 'b', 'x']);
    const box = deserializeEncryptedBox(setup.encryptedServerKey);
    const serverKey = decryptWithPrivateKey(box, ownerKeypair.privateKey);
    const response = await psi.processRequestWithDecryptedKey(serverKey, request);

    const count = await psi.computeCardinality(clientKey, ['a', 'b', 'x'], setup.setupMessage, response);
    expect(count).toBe(2);
  }, 60000);
});
