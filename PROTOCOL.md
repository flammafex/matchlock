# Matchlock Protocol Specification

## Overview

Matchlock is a protocol for mutual preference detection. Two parties can discover they mutually selected each other without either party or the server learning about unilateral (non-mutual) selections.

## Participants

- **Participant**: A user with an X25519 keypair. Derives match tokens locally.
- **Pool owner**: Holds the PSI server key (encrypted). Processes PSI queries.
- **Server**: Stores encrypted PSI setup and queues PSI requests. Learns nothing about preferences.

## Protocol

### Phase 1: Key generation

Each participant generates an X25519 keypair out-of-band:

```
(priv_i, pub_i) ← X25519.keygen()
```

Public keys are published to the pool.

**Security note:** The private key is used for both DH matching and nullifier derivation. It must never leave the client.

### Phase 2: Token derivation

For each participant j that participant i wants to select:

```
shared_ij = X25519(priv_i, pub_j)
token_ij  = SHA256(shared_ij || pool_id || "rendezvous-match-v1")
```

By X25519 commutativity: `shared_ij == shared_ji`, therefore `token_ij == token_ji`.

A match token is identical for both parties iff both derived it — which requires both to have selected each other.

**Note on domain separator ordering:** The pool_id and domain constant are concatenated after the shared secret without a length prefix. This is safe because the domain constant is a compile-time fixed string, making collisions between `(pool_id, domain)` pairs unreachable in practice.

### Phase 3: Commitment (optional, prevents timing attacks)

```
commit_ij = SHA256(raw_bytes(token_ij))
```

The commitment is SHA-256 of the 32 raw bytes encoded by the token hex string, not of the hex string itself. Participants submit commitments first, then reveal tokens after a deadline.

### Phase 4: Nullifier generation

```
nullifier_i = SHA256(priv_i_bytes || pool_id || "rendezvous-nullifier-v1")
```

Nullifiers prevent a participant from submitting multiple preference sets within a pool, while remaining unlinkable across pools.

### Phase 5: PSI setup (pool owner)

```
(psi_server_key, setup_msg) ← PSI.server_setup(all_tokens)
encrypted_key = ECIES_encrypt(psi_server_key, owner_pub)
```

`setup_msg` is public. `encrypted_key` is stored on the server but the server cannot decrypt it.

### Phase 6: PSI query (participant)

```
(psi_request, client_key) ← PSI.client_request(my_tokens)
```

The server learns request size but not its contents.

### Phase 7: PSI processing (pool owner)

```
psi_server_key = ECIES_decrypt(encrypted_key, owner_priv)
psi_response   = PSI.process_request(psi_server_key, psi_request)
```

### Phase 8: Intersection computation (participant)

```
match_indices = PSI.compute_intersection(client_key, my_tokens, setup_msg, psi_response)
matches = [my_tokens[i] for i in match_indices]
```

Only the querier learns the result.

**Important:** `my_tokens` must be the same array in the same order as submitted in Phase 6.

## Cryptographic primitives

| Primitive | Algorithm | Library |
|-----------|-----------|---------|
| Key agreement | X25519 | @noble/curves |
| Token hashing | SHA-256 | @noble/hashes |
| Commitment | SHA-256 (of raw bytes) | @noble/hashes |
| Asymmetric encryption | X25519 + HKDF + XChaCha20-Poly1305 | @noble/curves, @noble/hashes, @noble/ciphers |
| PSI | ECDH-based PSI | @openmined/psi.js |
| Signing (owner auth) | Ed25519 + SHA-256 domain separation | @noble/curves |

## Security properties

**Unilateral privacy**: `T_ij = SHA256(DH(priv_i, pub_j) || ...)` is computationally indistinguishable from random to anyone without `priv_i` or `priv_j`.

**Server opacity**: The server stores only opaque base64 PSI artifacts and cannot interpret them without the owner's private key.

**Owner-held key trust model**: The PSI server key is ECIES-encrypted to the pool owner's X25519 public key. A compromised server operator cannot process PSI queries retroactively.

**Pool isolation**: The `pool_id` domain separator ensures tokens from different pools are independent.

## Out of scope

- Sybil resistance (use Freebird for anonymous rate-limited authorization)
- Timestamping (use Witness for threshold timestamps)
- Transport security (use TLS)
- Metadata privacy (timing, IP, message sizes)
