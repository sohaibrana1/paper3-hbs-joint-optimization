# Paper 3 Correctness and Validation Plan

## C1 Normal verification

For every measured implementation variant:

Sign(m) -> sigma

Verify(pk, m, sigma) must return PASS.

Required publication benchmark result:

100 percent measured-signature verification success.

## C2 Modified-message rejection

After generating a valid signature, flip one bit of the message.

Verify(pk, modified_message, sigma) must return FAIL.

## C3 Corrupted-signature rejection

Flip one bit of a valid signature.

Verify(pk, m, corrupted_sigma) must return FAIL.

## C4 Truncated-signature rejection

Where the API accepts explicit signature lengths, remove at least one
byte from a valid signature.

Verification must return FAIL or a defined format/length error.

No memory-safety failure is acceptable.

## C5 Compression round trip

For lossless compression experiments:

decompress(compress(sigma)) == sigma

must hold byte-for-byte.

## C6 Compact-state round trip

For each compact state implementation:

state_original
-> serialize
-> deserialize
-> state_recovered

The recovered state must produce correct subsequent signing behavior.

No index reuse is permitted.

## C7 XMSS h=10 exhaustion test

Generate and verify all:

2^10 = 1024

valid sequential signatures.

Attempting signature index 1024 must be rejected.

## C8 XMSS h=16 persistence test

Generate at least:

2048

sequential signatures.

Persist and reload state every 128 signatures.

Required conditions:

- all signatures verify
- signing index is strictly monotonic
- no index reuse occurs
- recovered state resumes at the correct next index

## C9 XMSSMT H=20 d=2 rollover test

Generate:

1030

sequential signatures.

This crosses the lower-tree boundary at:

2^10 = 1024.

Required conditions:

- signatures 0 through 1029 verify
- rollover is completed correctly
- no signing-index reuse occurs
- compact and baseline implementations preserve equivalent external behavior

## C10 Parallel correctness

SEQ, PAR1, PAR2, and PAR4 outputs must all verify.

Parallel execution must never permit concurrent modification of
stateful signing indices.

## C11 Streaming correctness

Streaming signing output must reconstruct the same complete valid
signature format expected by verification.

Streaming verification must accept valid streamed signatures and
reject corrupted signatures.

## C12 Failure criterion

Any new implementation variant that fails correctness validation is
excluded from performance/Pareto claims until corrected and rerun.

Performance measurements do not override correctness failures.
