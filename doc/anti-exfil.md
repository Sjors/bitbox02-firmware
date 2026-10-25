# Draft Taproot anti-exfiltration

This experimental implementation uses the single-signer BIP-EXFIL protocol for
Taproot key-path signatures. It is independent of the existing ECDSA anti-klepto
message format and nonce domain. The `DeviceInfoResponse.taproot_anti_exfil`
capability must be true before a host starts this flow.

The host invokes transaction review twice. `BTCSignInitRequest.taproot_anti_exfil_round`
is 1 for a commitment-only invocation and 2 for signing. Every input in the second
input pass must contain `BTCTaprootAntiExfil` for that invocation's round. Transcript
fields in the first input pass, mixed ordinary/AE inputs, mixed rounds, malformed
lengths, unsupported sighashes, and script-path signing are rejected.

The per-input message contains `host_commitment` (32 bytes), `signer_nonce` (33
bytes), `host_entropy` (32 bytes), and `sighash` (0 DEFAULT or 1 ALL). The commitment
invocation leaves the nonce and entropy empty. Its responses carry
`BTCSignNextResponse.taproot_anti_exfil_nonce` and never a signature. The host records
all 33 bytes, including parity, before creating its reveal invocation. The signing
invocation carries the original commitment, original nonce, and opening; the signer
checks both, adds the host scalar to the deterministically derived secret nonce,
and verifies the BIP340 signature before releasing it. The actual Taproot-tweaked
output key is used by both rounds. Secret scalars are cleared when no longer needed.

Hosts must independently select the expected output key and BIP341 message,
verify the ordinary BIP340 signature and `sig.r == x(R0 + rho*G)`, and reject
changed transactions, UTXOs, transcript fields, sighashes, or extra signatures.
Transport participation alone is not anti-exfil verification. HWI performs these
checks around its device adapter. The optional SDK arguments expose transport;
other applications must supply equivalent host verification themselves.

No secret nonce state persists between calls. An interrupted session must be
retried with the exact same transaction, keys, commitment, original nonce, and host
entropy. Never automatically restart with fresh host entropy after an abort.
The provisional `BIP-EXFIL/host` and `BIP-EXFIL/nonce` hash domains and shared test
vectors must change together when a BIP number is assigned.

`python3 test_anti_exfil.py` compiles the bundled libsecp dependency natively and
checks shared vectors, changed transcript rejection, and scalar-order boundaries.
`make simulator`, `make firmware-btc`, and `make run-rust-unit-tests` build/test the
firmware in the SDK selected by `.containerversion`. HWI's
`bitbox02_test_suite(..., anti_exfil=True)` exercises the real native simulator:
PSBT v0/v2, two BIP86 inputs, DEFAULT/ALL, reconnects, malformed requests injected
at the firmware boundary, host proof verification, broadcast, and confirmation.
