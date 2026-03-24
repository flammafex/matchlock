import { encryptForPublicKey, serializeEncryptedBox, } from '../dh/ecies.js';
export class PsiService {
    psi = null;
    initPromise = null;
    async init() {
        if (this.psi)
            return;
        if (this.initPromise)
            return this.initPromise;
        this.initPromise = (async () => {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const PSI = await import('@openmined/psi.js');
            const loadPsi = PSI.default ?? PSI;
            this.psi = await loadPsi();
        })();
        return this.initPromise;
    }
    async getPsi() {
        await this.init();
        if (!this.psi)
            throw new Error('PSI library not initialized');
        return this.psi;
    }
    /**
     * Create PSI setup with server key encrypted to owner's public key.
     * The server stores the encrypted blob but cannot access the plaintext key.
     */
    async createOwnerEncryptedSetup(request, ownerPublicKey) {
        const psi = await this.getPsi();
        if (!psi.server)
            throw new Error('PSI server not available');
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
    async processRequestWithDecryptedKey(serverKeyBase64, psiRequestBase64) {
        const psi = await this.getPsi();
        if (!psi.server)
            throw new Error('PSI server not available');
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
    async createRequest(inputs) {
        const psi = await this.getPsi();
        if (!psi.client)
            throw new Error('PSI client not available');
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
    async computeIntersection(clientKey, inputs, psiSetupBase64, psiResponseBase64) {
        const psi = await this.getPsi();
        if (!psi.client)
            throw new Error('PSI client not available');
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
    async computeCardinality(clientKey, inputs, psiSetupBase64, psiResponseBase64) {
        const psi = await this.getPsi();
        if (!psi.client)
            throw new Error('PSI client not available');
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
let psiService = null;
export function getPsiService() {
    if (!psiService)
        psiService = new PsiService();
    return psiService;
}
//# sourceMappingURL=service.js.map