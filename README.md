# Matchlock

Privacy-preserving mutual match: detect when two parties select each other without revealing unilateral selections to anyone.

## The problem

Every existing matching platform operates as a trusted intermediary that sees all preferences. They know who you selected and who selected you, including rejections. This is a structural surveillance problem, not an implementation detail.

## How Matchlock works

Matchlock composes two primitives:

**1. DH token derivation**

Two parties independently derive *identical* match tokens when they mutually select each other, using X25519 Diffie-Hellman:

```
Alice selects Bob:
  token = SHA256(DH(alice_priv, bob_pub) || poolId || "rendezvous-match-v1")

Bob selects Alice:
  token = SHA256(DH(bob_priv, alice_pub) || poolId || "rendezvous-match-v1")

// DH commutativity: same shared secret → same token
```

Tokens are derived locally. No server interaction required. The server never sees your selections — only the derived tokens you choose to submit.

**2. Private Set Intersection (PSI)**

PSI allows the server to detect overlapping tokens without learning which tokens each participant submitted. Built on [OpenMined's PSI.js](https://github.com/OpenMined/PSI) with an owner-held key architecture: the PSI server key is encrypted to the pool owner's public key, so the server cannot process queries without owner participation.

Together:

| Party | Learns | Does NOT learn |
|-------|--------|----------------|
| Server | Set sizes, timing | Your selections or matches |
| You | Your matches only | Who rejected you, or who others selected |
| Pool owner | Match token hashes | Whose key belongs to whom |

## Installation

```bash
npm install matchlock
```

## Usage

```typescript
import { generateKeypair, deriveMatchToken, PsiService } from 'matchlock';

const alice = generateKeypair();
const bob = generateKeypair();

// Both derive the same token (DH commutativity)
const tokenA = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
const tokenB = deriveMatchToken(bob.privateKey, alice.publicKey, 'pool-1');
console.log(tokenA === tokenB); // true — mutual match
```

See [`examples/mutual-match.ts`](examples/mutual-match.ts) for a complete end-to-end walkthrough.

## Security properties

- **Zero server knowledge**: The server sees only opaque hash values.
- **Unilateral privacy**: If Alice selects Bob but Bob doesn't select Alice, Bob learns nothing about Alice's selection.
- **Pool isolation**: Tokens are scoped to a pool ID. Cross-pool linkability requires breaking SHA-256.
- **Replay protection**: Nullifiers prevent re-submission within a pool while remaining unlinkable across pools.
- **Owner-held PSI keys**: The PSI server key is ECIES-encrypted to the pool owner's X25519 public key. The infrastructure operator cannot process PSI queries independently.

## Reference implementation

[Rendezvous](https://github.com/sophiaDOS/rendezvous) — a full matching application built on Matchlock, Freebird, and Witness.

## Part of SophiaDOS

Matchlock is one of three cryptographic primitives in the [SophiaDOS](https://github.com/sophiaDOS) ecosystem:

- **Matchlock** — privacy-preserving mutual matching (this library)
- **[Freebird](https://github.com/sophiaDOS/freebird)** — anonymous authorization via VOPRF blind signatures
- **[Witness](https://github.com/sophiaDOS/witness)** — threshold timestamping via BLS12-381

## License

Apache-2.0
