# KR-SEE: Kernel-Level Security & Memory Enforcement

KR-SEE is a kernel-level security framework and hardening toolkit focused on memory persistence control, anti-debugging, entropy management, and isolation. This README aims to present the conceptual ideas, precise mathematical invariants, and practical implementation notes with math rendered in standard LaTeX delimiters for clarity.

> Note about math rendering
>
> - This file uses LaTeX-style math delimiters: inline `$...$` and display `$$...$$`. Some Markdown viewers (GitHub Pages, many static site generators, and local Markdown previewers with KaTeX/MathJax enabled) will render this as formatted math.
> - If your viewer does not render LaTeX, every important equation is followed by a monospace/plain-text fallback so the formulas remain readable.

---

## Table of Contents

1. [Motivation](#motivation)  
2. [Core Principles](#core-principles)  
   - [Memory Persistence](#memory-persistence)  
   - [Anti-Debugging](#anti-debugging)  
   - [Entropy Decay](#entropy-decay)  
   - [Failure Semantics](#failure-semantics)  
   - [Kernel-Level Isolation](#kernel-level-isolation)  
   - [Temporal Integrity Patrol (Watchdog)](#temporal-integrity-patrol-watchdog)  
3. [Threat Model](#threat-model)  
4. [Architecture](#architecture)  
5. [How to View Math / Tips](#how-to-view-math--tips)  
6. [Acknowledgments](#acknowledgments)

---

## Motivation

Modern systems often fail to protect secrets in memory against low-level attacks such as:

- Cold-boot attacks
- ptrace / debugging attacks
- Swap / pagefile analysis
- Exploit-triggered panics

KR-SEE formalizes and enforces memory-bound secrets, continuous anti-observation guarantees, and runtime hardening.

---

## Core Principles

### 1. Memory Persistence

Requirement: secrets must live only in RAM and must not persist to disk or swap.

Formal invariant (display math):
$$
K \in R \quad\land\quad K \notin D
$$
Plaintext fallback: `K ∈ R  ∧  K ∉ D`

Time-to-live constraint:
$$
\mathrm{TTL}(K) = \mathrm{TTL}(R) < \infty
$$
Plaintext fallback: `TTL(K) = TTL(R) < ∞`

Practical measures:
- Use `mlock()` / mlockall() to pin pages.
- Disable swapping for pages holding secrets.
- Ensure memory is zeroized on release and that secrets vanish on power loss.

Code example (Rust-like zeroize):
```rust
// zeroize in place (fallback if zeroize crate not available)
for b in secret.as_mut_slice() { *b = 0; }
```

---

### 2. Anti-Debugging

Goal: only the process itself may observe its memory or execution state.

Notation:
- Let `P` be a process.
- `Obs(P)` is the set of observers of `P`.

Invariant:
$$
\mathrm{Obs}(P) = \{P\}
$$
Fallback: `Obs(P) = { P }`

Failure (observed by an external entity):
$$
\mathrm{Obs}(P) = \varnothing \;\Rightarrow\; \exists \text{Attacker}: \text{Attacker} \to P
$$
Fallback: `Obs(P) = ∅ ⇒ ∃ Attacker : Attacker → P`

Reality note: Kernel-level policies and continuous monitoring are required — a one-time check at startup is insufficient.

---

### 3. Entropy Decay

Secrets are defined by their high entropy. On deletion, entropy must tend to zero.

Formal:
$$
\lim_{t \to t_{\mathrm{end}}} H(K_t) = 0
$$
Fallback: `lim t→t_end H(K_t) = 0`

Practical steps:
- Track secret allocations in a registry.
- Overwrite memory deterministically (`zeroize`).
- Use secure memory scrubbing to avoid compiler optimizations that elide writes.

---

### 4. Failure Semantics

Crashes and panics are first-class considerations; failure handling must preserve secrecy.

Let:
- `C` be the cleanup routine.
- `F` be a failure event.

If a process aborts (panic with immediate abort), cleanup may not run. Formally:
$$
\text{panic} = \text{"abort"} \;\Rightarrow\; F \Rightarrow \text{Immediate Exit}
$$
Fallback: `panic = "abort" ⇒ F ⇒ Immediate Exit`

If cleanup is not part of the failure trace:
$$
C \notin \delta(F) \;\Rightarrow\; \exists F : H(K) > 0 \text{ at termination}
$$
Fallback: `C ∉ δ(F) ⇒ ∃ F : H(K) > 0 at termination`

Design implication: register panic hooks, ensure secure abort paths, and prefer process isolation strategies that allow secure teardown.

---

### 5. Kernel-Level Isolation

Assume the host may be partially untrusted. Use namespaces, user mappings, and seccomp to reduce attack surface.

Notation:
- `S` = set of all Linux syscalls.
- `A` = allowed syscalls.

Invariant:
$$
A \subset S, \quad |A| \approx 50
$$
Fallback: `A ⊂ S, |A| ≈ 50`

Policy:
- Strict seccomp filters in trap mode.
- Minimal syscall whitelist.
- Namespaces (`unshare`) for user & mount isolation.

---

### Temporal Integrity Patrol (Watchdog)

A static anti-debugging check is a point-in-time guarantee and can be bypassed later. KR-SEE enforces a temporal invariant using a watchdog thread.

Definitions:
- `T_guard` = background patrol thread.
- `T_main` = primary thread holding secrets.
- `Trace(A, B)` = boolean: A successfully ptrace-attaches to B.

Temporal invariant:
$$
\forall t\in [t_{\text{start}},t_{\text{end}}] \;:\; \mathrm{Trace}(T_{\text{guard}}, T_{\text{main}}) = \text{True}
$$
Fallback: `∀ t ∈ [t_start, t_end] : Trace(T_guard, T_main) = True`

Implementation sketch:
- Spawn `T_guard` after namespace isolation.
- Every 500 ms, attempt to seize the ptrace slot of `T_main`.
- If ptrace slot is taken (EPERM or equivalent), trigger immediate entropy decay (secure wipe and safe shutdown).
- Transition on detection:
  $$ \exists t_i : \mathrm{Trace}(T_{\text{guard}},T_{\text{main}}) = \text{False} \Rightarrow \delta(F) $$
  Fallback: `∃ t_i : Trace(T_guard, T_main) = False ⇒ δ(F)`

---

## Threat Model

KR-SEE defends against:
- Memory dumping / cold-boot attacks
- Debugging & ptrace attacks
- Unauthorized syscall execution via untrusted processes
- Crash/panic-based data leakage

KR-SEE does NOT provide protection against:
- Arbitrary kernel exploits (root compromise)
- Hardware-level attacks (physical bus snooping, DMA attacks on unprotected hardware)

---

## Acknowledgments

- Linux Kernel documentation and the open-source security community.

---
