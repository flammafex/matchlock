import type {
  CreatePsiSetupRequest,
  OwnerHeldPsiSetup,
  PsiResult,
} from './types.js';
import {
  encryptForPublicKey,
  serializeEncryptedBox,
} from '../dh/ecies.js';

// PSI v2 types
interface PsiLibrary {
  server?: {
    createWithNewKey(revealIntersection?: boolean): PsiServer;
    createFromKey(key: Uint8Array, revealIntersection?: boolean): PsiServer;
  };
  client?: {
    createWithNewKey(revealIntersection?: boolean): PsiClient;
    createFromKey(key: Uint8Array, revealIntersection?: boolean): PsiClient;
  };
  serverSetup: {
    deserializeBinary(bytes: Uint8Array): PsiServerSetup;
  };
  request: {
    deserializeBinary(bytes: Uint8Array): PsiRequest;
  };
  response: {
    deserializeBinary(bytes: Uint8Array): PsiResponse;
  };
  dataStructure: {
    GCS: number;
    BloomFilter: number;
  };
}

interface PsiServer {
  createSetupMessage(fpr: number, numClientInputs: number, inputs: readonly string[], dataStructure?: number): PsiServerSetup;
  processRequest(request: PsiRequest): PsiResponse;
  getPrivateKeyBytes(): Uint8Array;
}

interface PsiClient {
  createRequest(inputs: readonly string[]): PsiRequest;
  getIntersection(setup: PsiServerSetup, response: PsiResponse): number[]; // returns INDICES
  getIntersectionSize(setup: PsiServerSetup, response: PsiResponse): number;
  getPrivateKeyBytes(): Uint8Array;
}

interface PsiServerSetup {
  serializeBinary(): Uint8Array;
}

interface PsiRequest {
  serializeBinary(): Uint8Array;
}

interface PsiResponse {
  serializeBinary(): Uint8Array;
}

export class PsiService {
  private psi: PsiLibrary | null = null;
  private initPromise: Promise<void> | null = null;

  async init(): Promise<void> {
    if (this.psi) return;
    if (this.initPromise) return this.initPromise;
    this.initPromise = (async () => {
      const PSI = await import('@openmined/psi.js');
      this.psi = await PSI.default() as unknown as PsiLibrary;
    })();
    return this.initPromise;
  }

  private async getPsi(): Promise<PsiLibrary> {
    await this.init();
    if (!this.psi) throw new Error('PSI library not initialized');
    return this.psi;
  }

  /**
   * Create PSI setup with server key encrypted to owner's public key.
   * The server stores the encrypted blob but cannot access the plaintext key.
   */
  async createOwnerEncryptedSetup(
    request: CreatePsiSetupRequest,
    ownerPublicKey: string,
  ): Promise<OwnerHeldPsiSetup> {
    const psi = await this.getPsi();
    if (!psi.server) throw new Error('PSI server not available');

    const fpr = request.fpr ?? 0.001;
    const maxClientElements = request.maxClientElements ?? 10000;

    const server = psi.server.createWithNewKey(true);
    const setup = server.createSetupMessage(fpr, maxClientElements, request.matchTokens);
    const privateKey = server.getPrivateKeyBytes();
    const privateKeyBase64 = Buffer.from(privateKey).toString('base64');
    const encryptedBox = encryptForPublicKey(privateKeyBase64, ownerPublicKey);

    return {
      poolId: request.poolId,
      setupMessage: Buffer.from(setup.serializeBinary()).toString('base64'),
      encryptedServerKey: serializeEncryptedBox(encryptedBox),
      ownerPublicKey,
      fpr,
      maxClientElements,
      dataStructure: 'GCS',
      createdAt: Date.now(),
    };
  }

  /**
   * Process a PSI request using a decrypted server key.
   * Called by the pool owner after they decrypt the key locally.
   */
  async processRequestWithDecryptedKey(
    serverKeyBase64: string,
    psiRequestBase64: string,
  ): Promise<string> {
    const psi = await this.getPsi();
    if (!psi.server) throw new Error('PSI server not available');

    const serverKey = new Uint8Array(Buffer.from(serverKeyBase64, 'base64'));
    const server = psi.server.createFromKey(serverKey, true);

    const requestBytes = new Uint8Array(Buffer.from(psiRequestBase64, 'base64'));
    const request = psi.request.deserializeBinary(requestBytes);
    const response = server.processRequest(request);

    return Buffer.from(response.serializeBinary()).toString('base64');
  }

  /**
   * Create a PSI request (client side).
   * Returns the request to send and the client key needed to compute intersection later.
   */
  async createRequest(inputs: string[]): Promise<{ request: string; clientKey: string }> {
    const psi = await this.getPsi();
    if (!psi.client) throw new Error('PSI client not available');

    const client = psi.client.createWithNewKey(true);
    const request = client.createRequest(inputs);

    return {
      request: Buffer.from(request.serializeBinary()).toString('base64'),
      clientKey: Buffer.from(client.getPrivateKeyBytes()).toString('base64'),
    };
  }

  /**
   * Compute intersection (client side).
   * Only the caller learns the result.
   * Note: PSI v2 getIntersection returns indices; we map back to strings.
   * @param inputs - MUST be identical in content and order to the array passed to createRequest.
   *   The PSI library replays the request internally to restore OPRF state.
   */
  async computeIntersection(
    clientKey: string,
    inputs: string[],
    psiSetupBase64: string,
    psiResponseBase64: string,
  ): Promise<PsiResult> {
    const psi = await this.getPsi();
    if (!psi.client) throw new Error('PSI client not available');

    const keyBytes = new Uint8Array(Buffer.from(clientKey, 'base64'));
    const client = psi.client.createFromKey(keyBytes, true);

    // Must call createRequest again to restore internal state before getIntersection
    client.createRequest(inputs);

    const setupBytes = new Uint8Array(Buffer.from(psiSetupBase64, 'base64'));
    const responseBytes = new Uint8Array(Buffer.from(psiResponseBase64, 'base64'));
    const setup = psi.serverSetup.deserializeBinary(setupBytes);
    const response = psi.response.deserializeBinary(responseBytes);

    // v2: getIntersection returns number[] (indices into inputs array)
    const indices = client.getIntersection(setup, response);
    const intersection = indices.map(i => inputs[i]);

    return { intersection, cardinality: intersection.length };
  }

  /**
   * Compute only cardinality (client side).
   * @param inputs - MUST be identical in content and order to the array passed to createRequest.
   *   The PSI library replays the request internally to restore OPRF state.
   */
  async computeCardinality(
    clientKey: string,
    inputs: string[],
    psiSetupBase64: string,
    psiResponseBase64: string,
  ): Promise<number> {
    const psi = await this.getPsi();
    if (!psi.client) throw new Error('PSI client not available');

    const keyBytes = new Uint8Array(Buffer.from(clientKey, 'base64'));
    const client = psi.client.createFromKey(keyBytes, false);

    client.createRequest(inputs);

    const setupBytes = new Uint8Array(Buffer.from(psiSetupBase64, 'base64'));
    const responseBytes = new Uint8Array(Buffer.from(psiResponseBase64, 'base64'));
    const setup = psi.serverSetup.deserializeBinary(setupBytes);
    const response = psi.response.deserializeBinary(responseBytes);

    return client.getIntersectionSize(setup, response);
  }
}

let psiService: PsiService | null = null;

export function getPsiService(): PsiService {
  if (!psiService) psiService = new PsiService();
  return psiService;
}
