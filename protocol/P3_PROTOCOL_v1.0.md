# Paper 3 Experimental Protocol v1.0

## Working title

Size and Memory Co-Optimization of Hash-Based Signatures on Raspberry Pi 5:
Compact State, Compression, Hash Backends, Streaming, and Parallel Execution

## Study objective

Evaluate size, persistent-state, working-memory, and computational
optimizations for stateful and stateless hash-based signatures on
Raspberry Pi 5 while preserving correctness and explicitly separating
standard-compatible configurations from experimental constructions.

## Primary research question

How much can the transmission, persistent-state, and working-memory
costs of hash-based signatures be reduced on Raspberry Pi 5 while
preserving cryptographic correctness and quantifying latency, memory,
code-size, and implementation trade-offs?

## Principal parameter sets

1. XMSS-SHA2_10_256
2. XMSS-SHA2_16_256
3. XMSSMT-SHA2_20-2_256
4. SLH-DSA-SHA2-128s
5. SLH-DSA-SHA2-128f

For the principal XMSS/XMSSMT experiments:

- n = 32 bytes
- WOTS+ w = 16
- XMSS heights = 10 and 16
- XMSSMT total height = 20
- XMSSMT layers = 2

No additional WOTS+ parameter sweep is part of Paper 3.

## Experimental modules

### Module A: Compression

Evaluate:

- raw signatures
- zlib level 6
- zstd level 3
- SPHINCS+ baseline
- SPHINCS+C research construction

Generic compression is treated as a compressibility control rather
than a cryptographic novelty.

Any proposed new signature-compression construction remains inactive
until its encoder, decoder, byte representation, correctness
requirements, and security implications are separately specified.

### Module B: Compact state

Evaluate XMSS and XMSSMT FAST/BDS against compact-state
representations and an appropriate memory-efficient literature
baseline where implementation compatibility permits.

Primary state metrics:

- serialized secret/state bytes
- peak working memory
- peak heap
- peak stack
- serialization latency
- deserialization latency
- signing latency
- key-generation latency

### Module C: Hash backends

Stateful controlled matrix:

- SHA2
- SHAKE
- Haraka
- ASCON

Structures:

- XMSS h=10
- XMSS h=16
- XMSSMT H=20, d=2

WOTS+ remains fixed at w=16.

SHA2 and SHAKE are standards-oriented baselines where applicable.
Haraka and ASCON configurations are explicitly experimental.

SLH-DSA comparison:

- SHA2-128s
- SHAKE-128s
- SHA2-128f
- SHAKE-128f

### Module D: Multicore execution

Execution modes:

- SEQ
- PAR1
- PAR2
- PAR4

PAR1 measures parallel-framework overhead independently of multicore
speedup.

Parallel work must not introduce concurrent mutation of XMSS signing
state or signing indices.

### Module E: Low-memory SLH-DSA

Memory modes:

- FULL_BUFFER
- BUFFER_REUSE
- STREAM

Streaming benchmarks must exclude filesystem and network I/O from
cryptographic timing.

### Module F: Combined optimization

Only predefined staged combinations are evaluated.

No exhaustive factorial combination is permitted.

Intermediate results define:

STATE_STAR = correctness-valid state representation with minimum
serialized state size; ties resolved by peak RAM.

HASH_STAR = faster of SHA2 and SHAKE by median signing latency; a
difference within 2 percent is resolved by smaller binary size.

PAR_STAR = worker count among 1, 2, and 4 with minimum median latency;
ties are resolved in favor of fewer workers.

Experimental Haraka/ASCON configurations do not determine the
standards-oriented combined design.

## Measurement protocol

Primary cryptographic benchmark counts per independent process:

- KeyGen: 10
- Sign: 100
- Verify: 100

Independent process repeats:

- 3

Stateful signature structure:

- 10 independently generated keys
- 10 consecutive measured signatures per key
- measured signature indices 0 through 9

Warm-up material must be independent of measured key material.

Warm-up operations are not included in publication statistics.

## Timing

Primary wall-clock timing source:

CLOCK_MONOTONIC_RAW

Timing is recorded in nanoseconds.

Memory-instrumented builds must not be used as the authoritative
latency build.

## CPU cycles

Hardware CPU-cycle counters are preferred.

For multithreaded execution, total CPU consumption is the sum of
per-worker cycles where technically available.

Wall-clock-derived pseudo-cycle counts are prohibited.

## Parallel metrics

Speedup:

S_p = T_1 / T_p

Efficiency:

E_p = S_p / p

Parallel-framework overhead:

O_thread = 100 * (T_PAR1 - T_SEQ) / T_SEQ

## Signature-size metric

R_sigma = 100 * (1 - compressed_signature_bytes / original_signature_bytes)

## State-size metric

R_state = 100 * (1 - optimized_state_bytes / baseline_state_bytes)

## Working-memory metric

R_RAM = 100 * (1 - optimized_peak_RAM / baseline_peak_RAM)

## Correctness

Every new implementation must pass:

- normal signature verification
- modified-message rejection
- corrupted-signature rejection
- truncated-signature rejection where applicable
- serialization/deserialization validation
- compression/decompression byte-exact round trip where applicable

Long-sequence state tests are defined separately in
P3_CORRECTNESS_PLAN.md.

## Statistical unit

Individual signatures belonging to the same process/key are not
automatically treated as fully independent observations.

Stateful analysis uses 10 key-level signing batches per process.

With three independent process repeats:

3 x 10 = 30 principal batch-level observations per configuration.

For stateless signing, the 100 operations are grouped into ten
predefined blocks per process, producing the same 30 block-level
analysis units.

## Descriptive statistics

Report:

- n
- arithmetic mean
- standard deviation
- median
- IQR
- minimum
- maximum
- 95 percent confidence interval

Median and bootstrap confidence intervals are the primary robust
latency summaries.

## Pareto analysis

Maintain separate frontiers:

P_std = standards-compatible configurations

P_exp = experimental/research configurations

Candidate objectives include:

- signature bytes
- serialized state bytes
- peak RAM
- KeyGen latency
- signing latency
- verification latency
- binary/code size

No universal weighted "best configuration" score will be used.

## Scope exclusions

Paper 3 excludes:

- another broad WOTS+ sweep
- XMSSMT 20/4 main-matrix experiments
- SLH-DSA 192/256 main-matrix experiments
- Windows benchmarking
- TLS/PKI integration
- blockchain deployment
- secure-boot deployment
- fault-injection studies
- side-channel studies
- FPGA/ASIC acceleration
- constant-sum WOTS+
- claims that experimental Haraka/ASCON XMSS variants are standardized
- new compression designs introduced without a prior formal specification

## Reproducibility

Each publication run must record:

- Git commit
- source-manifest SHA-256
- executable SHA-256
- compiler/version
- compiler flags
- CPU affinity
- worker count
- CPU governor
- CPU frequency metadata
- temperature metadata
- throttling status
- experiment ID
- repeat ID

Any run with observed thermal throttling is invalidated and repeated.

## Protocol versioning

This file is version 1.0.

Changes after freeze require a new protocol version and written reason.
The frozen v1.0 file must not be silently overwritten.
