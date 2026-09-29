# A Pi-Based Rekeying Scheme: Design, Attack, and Hardening

**Author:** Alexander, independent student (I'm just curious as to how things work)
**Status:** Student research draft. Not peer reviewed. Not for production use.

---

## Abstract

This paper studies a proposed key-evolution scheme in which a 256-bit secret selects positions in the digits of pi, and windows of those digits are transformed (shifted, encoded, swapped) to produce changing key material between servers. We first show that the naive linear design, `x(t) = x0 + c·t`, is insecure under a known-window attack, because pi is public and the walk is affine. We then present a hardened design that keeps pi as a public "nothing-up-my-sleeve" table but moves all security into standard, analyzed primitives: HKDF-based derivation, a one-way ratchet, Shamir secret sharing with proactive refresh, and a transcript-derived visual fingerprint. We state a threat model, evaluate each component honestly, and propose experiments. Our conclusion is that pi contributes no security in any variant, but the hardened structure is sound and makes a useful teaching and experimental platform. (This is all started with a random thought about what could pi possibly do in cryptography, SPOILER: nothing useful)

## 1. Introduction

Pi's digits pass many statistical randomness tests, which motivates the idea of using them as a source of unpredictable key material. The goal of this work is to test that idea against an adversary who knows the full algorithm, following Kerckhoffs's principle [1]: a system must remain secure when everything except the key is public.

**Contributions**

1. A precise description of the original scheme and its known-window attack.
2. A hardened architecture built from established primitives.
3. An honest per-component evaluation, including which proposed ideas add no security.
4. An experimental plan to measure leakage and validate the fixes.

## 2. Threat Model

- **Attacker knowledge:** the full algorithm, source code, and the public digits of pi (a precomputed table of size `L`).
- **Network capability:** passive sniffing of all LAN traffic and active injection or modification.
- **Compromise capability:** full compromise of up to `k-1` of `n` servers at any given time (a mobile adversary that may compromise different servers in different epochs).
- **Goals:** confidentiality of session keys, forward secrecy, and detection of man-in-the-middle attacks.
- **Out of scope:** side channels, physical attacks, denial of service, and quantum adversaries against the key-exchange layer (discussed in Section 8).

## 3. The Original Scheme

Let `x0` be a secret starting index, `c` a speed, and `t` the step. The position and traveled distance are:

```
x(t) = x0 + c·t
Δx(t) = c·t
```

Each element of a sliding-window matrix is:

```
A_ij(t) = f( x0 + c·t + (i-1)·N + (j-1) )
```

where `N` is the number of columns and `f` maps a digit to an output symbol. The secret is `x0`.

### 3.1 Why it fails

1. **Public plaintext.** Pi is known to everyone. An observed window of `w` output digits can be located in the public table by suffix-array lookup, revealing `x0`. Two consecutive observations reveal `c`, after which all future output is known.
2. **Effective keyspace.** Realistic tables hold about 10^13 to 10^15 digits, so the usable index space is roughly 2^43 to 2^50, not 2^256.
3. **No nonlinearity.** The position is affine in the secret and in time, so there is no diffusion or one-wayness.
4. **Undefined `f`.** The mapping `f` is never specified, and the security analysis depends on it.

## 4. Evaluation of Proposed Components

Each idea is rated on its own security value, assuming the attacker knows the algorithm.

| Component | Honest standing |
|---|---|
| Key-dependent ruleset | Harmless if driven by a PRF over the whole key and placed before a hash. Alone, it is a transposition/substitution cipher that leaks digit histograms and repetition patterns. |
| Shorter windows | Reduces structural leakage but also reduces entropy contributed (about 3.3 bits per digit). A tradeoff, not a fix. |
| Layering | A cascade of independent, keyed, nonlinear layers is at least as strong as its strongest layer. Stacking permutations collapses into one permutation. |
| Kerberos-style central server | Legitimate architecture. The rule-making server is a single point of compromise and failure (see golden-ticket attacks) [7]. |
| Hash-derived index | **Strong.** `pos = H(K ‖ t) mod L` is unpredictable without `K`. The hash provides the security, not the table. |
| XOR / Shamir sharing | **Strong.** Information-theoretic secrecy below threshold [2]. |
| Proactive share refresh | **Strong** against mobile adversaries [3]. |
| Human-verifiable fingerprint | **Strong** against man-in-the-middle when derived from the handshake transcript. |
| Reset on compromise | **Strong in principle**, with a hard requirement (Section 5.6). |

## 5. Hardened Design

### 5.1 Overview

1. A 256-bit master secret `K` is generated by a CSPRNG and split among `n` servers with `k`-of-`n` Shamir sharing.
2. Servers communicate over mutually authenticated encrypted channels (Noise or TLS 1.3 with the PSK and an ephemeral X25519 exchange).
3. Each epoch `t`, servers derive a fresh session key through a keyed pipeline whose final stage is HKDF [4].
4. The master state is ratcheted forward one-way after every epoch.
5. A fingerprint of the handshake transcript is displayed for human verification.
6. Shares are refreshed proactively each epoch.

### 5.2 Keyed pi-window derivation

```
pos    = H(K ‖ t) mod L
W      = pi[pos .. pos+w]                 # public digits
ops    = HKDF-Expand(K, "ops" ‖ t)        # drives shift/encode/swap
W'     = swap(shift(encode(W, ops), ops), ops)
K_t    = HKDF(ikm = K, salt = W', info = "epoch" ‖ t)
K      = H(K ‖ "next")                    # one-way ratchet; erase old K
```

Because `W'` enters HKDF as salt and never as a key or keystream, the classical-cipher weaknesses of the transforms never reach the output. This also means the transforms cannot strengthen the result. Replacing pi with any public table leaves the security unchanged.

### 5.3 Key sections

Instead of splitting `K` into independently walking sections (which permits divide-and-conquer), subkeys are derived: `K_i = HKDF(K, "section-i")`. For custody splitting across servers, Shamir sharing over a prime field is used.

### 5.4 Proactive refresh

Each epoch, every server picks a random polynomial with zero constant term and sends each peer its evaluation over the authenticated channels. Each server adds the received values to its share and erases the old share. `K` is unchanged, but shares from different epochs cannot be combined [3].

### 5.5 Human-verifiable fingerprint

```
F = Truncate_100( H("fingerprint" ‖ transcript) )
```

`F` is rendered as a 5×5 grid of 16 colors (100 bits). Administrators compare the images over a separate channel. The derivation is one-way and domain-separated so the image reveals nothing about key material. This is the same idea as SSH randomart and Signal safety numbers. A separate cosmetic visualization of the pi pipeline may be shown for demonstrations, but it must never be used as a fingerprint.

### 5.6 Reset on compromise

When a node is flagged compromised, the system revokes it and restarts from a new starting point with a fully regenerated ruleset. This is a sound idea (key revocation and re-keying), but it has one requirement that is easy to violate: **the new state must not be derivable from anything the compromised node knew.**

- If the new start is `HKDF(old K, ...)`, the attacker who stole `old K` computes the new state too. The reset achieves nothing.
- The new master must be built from fresh randomness contributed by uncompromised parties (for example, a distributed key generation among the remaining honest servers, or re-provisioning from an offline root).
- Detection is the hard part. Reset only triggers if the compromise is noticed, and a stealthy attacker may never trigger it. Periodic proactive refresh limits the damage window regardless.

## 6. Comparison with Deployed Methods

| Method | Strengths | Weaknesses |
|---|---|---|
| AES-256-GCM / ChaCha20-Poly1305 (PSK) | Heavily analyzed, fast | Nonce reuse is catastrophic; no forward secrecy alone; distribution unsolved |
| TLS 1.3 / mTLS [5] | Forward secrecy, authenticated | CA trust, 0-RTT replay, implementation bugs, quantum-vulnerable key exchange |
| Noise / WireGuard [6] | Small, formally analyzed | Manual static-key management; PQ only via PSK |
| Double Ratchet (Signal) | Forward secrecy and post-compromise recovery | Complex; no protection once an endpoint is compromised |
| Shamir / proactive sharing | Information-theoretic below threshold | Dealer trust; key exposed at reconstruction; heavy operations |
| KMS / HSM | Root key never leaves hardware | Vendor trust; API abuse without key theft |
| Kerberos [7] | Central control, single sign-on | KDC is a single point of compromise; clock sync |
| Post-quantum (ML-KEM, hybrid) | Quantum resistance | Young; SIKE was broken classically in 2022; larger keys |
| QKD | Physics-based | Special hardware, distance limits, needs classical authentication, side-channel attacks |

The hardened design in Section 5 is essentially a composition of the rows for Noise/TLS, Double Ratchet, and proactive sharing. It introduces no capability those lack, and it has far less review behind it.

## 7. Results

1. **Known-window attack (naive).** Give the attacker `w` output digits and the full pi table. Measure time and success rate for recovering `x0` and `c` as `w` and `L` vary.
2. **Histogram-filter attack (keyed pipeline without hash).** Filter table positions by digit counts and repetition pattern. Plot surviving candidates versus window length. This quantifies the leakage-versus-entropy tradeoff of short windows.
3. **Hardened design under the same attacks.** Confirm that the attacker's advantage is no better than guessing `K`.
4. **Statistical testing.** NIST SP 800-22 and Dieharder on output of both designs. Passing tests is necessary but not sufficient evidence of security.
5. **Compromise simulation.** With `n` servers and one fully compromised, measure exposure under naive per-server rulesets versus HKDF-derived pairwise keys.
6. **Proactive refresh.** Demonstrate that shares from different epochs fail to reconstruct `K`.
7. **Reset correctness.** Test that a reset seeded from old state is recoverable by the attacker, and that a reset seeded with fresh honest entropy is not.

## 8. Limitations

- Pi's normality is unproven, so even its statistical randomness is an assumption.
- The design adds no security over its standard components and increases implementation surface.
- No formal proof is given. A real claim would need a defined security game and a reduction to the hardness of HKDF/hash primitives.
- Key exchange using X25519 is vulnerable to a future quantum adversary. A hybrid with ML-KEM would address this.
- Implementation side channels are not analyzed.

## 9. Conclusion

The original pi-walk fails because a public, deterministic sequence combined with an affine schedule leaks the secret from a single observation. Complexity of the path (zigzagging, swapping, layering) does not add entropy, because only the secret key provides that. The hardened variant is secure to the extent that its standard components are, and pi acts as decoration. The value of this work is methodological: stating a threat model, attacking one's own design, and identifying which ideas carry real security. Future work includes implementing the experiments above and evaluating a hybrid post-quantum handshake.

## References

1. A. Kerckhoffs, "La cryptographie militaire," *Journal des sciences militaires*, 1883.
2. A. Shamir, "How to Share a Secret," *Communications of the ACM*, 22(11), 1979.
3. A. Herzberg, S. Jarecki, H. Krawczyk, M. Yung, "Proactive Secret Sharing," CRYPTO 1995.
4. H. Krawczyk, P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)," RFC 5869, 2010.
5. E. Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3," RFC 8446, 2018.
6. T. Perrin, "The Noise Protocol Framework," 2018.
7. C. Neuman et al., "The Kerberos Network Authentication Service (V5)," RFC 4120, 2005.
8. M. Marlinspike, T. Perrin, "The Double Ratchet Algorithm," Signal specification, 2016.
9. B. Schneier, "Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)," 1994.
10. S. Fluhrer, I. Mantin, A. Shamir, "Weaknesses in the Key Scheduling Algorithm of RC4," 2001.
11. D. Bailey, P. Borwein, S. Plouffe, "On the Rapid Computation of Various Polylogarithmic Constants," 1997.
12. NIST SP 800-22, "A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications."
