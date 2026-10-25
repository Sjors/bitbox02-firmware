#ifndef BITBOX_ANTI_EXFIL_H
#define BITBOX_ANTI_EXFIL_H

#include <secp256k1.h>

/* Draft BIP-EXFIL. All keys are actual, already Taproot-tweaked signing keys.
 * The full compressed nonce (including parity) must be retained between rounds. */
int bitbox_anti_exfil_commit(
    const secp256k1_context* ctx,
    unsigned char nonce33[33],
    const unsigned char secret32[32],
    const unsigned char msg32[32],
    const unsigned char commitment32[32]);
int bitbox_anti_exfil_sign(
    const secp256k1_context* ctx,
    unsigned char signature64[64],
    const unsigned char secret32[32],
    const unsigned char msg32[32],
    const unsigned char commitment32[32],
    const unsigned char nonce33[33],
    const unsigned char entropy32[32]);

#endif
