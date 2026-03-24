import type { CreatePsiSetupRequest, OwnerHeldPsiSetup, PsiResult } from './types.js';
export declare class PsiService {
    private psi;
    private initPromise;
    init(): Promise<void>;
    private getPsi;
    /**
     * Create PSI setup with server key encrypted to owner's public key.
     * The server stores the encrypted blob but cannot access the plaintext key.
     */
    createOwnerEncryptedSetup(request: CreatePsiSetupRequest, ownerPublicKey: string): Promise<OwnerHeldPsiSetup>;
    /**
     * Process a PSI request using a decrypted server key.
     * Called by the pool owner after they decrypt the key locally.
     */
    processRequestWithDecryptedKey(serverKeyBase64: string, psiRequestBase64: string): Promise<string>;
    /**
     * Create a PSI request (client side).
     * Returns the request to send and the client key needed to compute intersection later.
     */
    createRequest(inputs: string[]): Promise<{
        request: string;
        clientKey: string;
    }>;
    /**
     * Compute intersection (client side).
     * Only the caller learns the result.
     * Note: PSI v2 getIntersection returns indices; we map back to strings.
     * @param inputs - MUST be identical in content and order to the array passed to createRequest.
     *   The PSI library replays the request internally to restore OPRF state.
     */
    computeIntersection(clientKey: string, inputs: string[], psiSetupBase64: string, psiResponseBase64: string): Promise<PsiResult>;
    /**
     * Compute only cardinality (client side).
     * @param inputs - MUST be identical in content and order to the array passed to createRequest.
     *   The PSI library replays the request internally to restore OPRF state.
     */
    computeCardinality(clientKey: string, inputs: string[], psiSetupBase64: string, psiResponseBase64: string): Promise<number>;
}
export declare function getPsiService(): PsiService;
//# sourceMappingURL=service.d.ts.map