#include "anti_exfil.h"

#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <string.h>

static void ae_clear(void* data, size_t len)
{
    volatile unsigned char* p = data;
    while (len--) {
        *p++ = 0;
    }
}

/* SHA256 results are below 2^256, so at most one subtraction is needed.
 * Select the reduced scalar without branching on secret nonce material. */
static void ae_reduce(unsigned char scalar[32])
{
    static const unsigned char order[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                                            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
                                            0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};
    unsigned char reduced[32];
    unsigned int borrow = 0;
    for (size_t i = 32; i-- > 0;) {
        const unsigned int difference = (unsigned int)scalar[i] - order[i] - borrow;
        reduced[i] = difference & 0xff;
        borrow = (difference >> 8) & 1;
    }
    const unsigned int mask = 0 - borrow;
    for (size_t i = 0; i < 32; ++i) {
        scalar[i] = (scalar[i] & mask) | (reduced[i] & ~mask);
    }
    ae_clear(reduced, sizeof(reduced));
}

typedef struct {
    const secp256k1_context* ctx;
    const unsigned char* commitment;
    const unsigned char* entropy;
} ae_nonce_data;

/* libsecp passes the even-Y normalized secret/public key to this callback. */
static int ae_nonce(
    unsigned char* nonce32,
    const unsigned char* msg,
    size_t msglen,
    const unsigned char* key32,
    const unsigned char* xonly32,
    const unsigned char* algo,
    size_t algolen,
    void* data)
{
    const ae_nonce_data* session = data;
    unsigned char aux[32], preimage[96];
    int ok = msglen == 32 && algo != NULL && algolen != 0;
    if (ok) {
        ok = secp256k1_tagged_sha256(
            session->ctx, aux, (const unsigned char*)"BIP0340/aux", 11, session->commitment, 32);
    }
    if (ok) {
        for (size_t i = 0; i < 32; ++i) {
            preimage[i] = key32[i] ^ aux[i];
        }
        memcpy(preimage + 32, xonly32, 32);
        memcpy(preimage + 64, msg, 32);
        ok = secp256k1_tagged_sha256(
            session->ctx,
            nonce32,
            (const unsigned char*)"BIP-EXFIL/nonce",
            15,
            preimage,
            sizeof(preimage));
    }
    if (ok) {
        ae_reduce(nonce32);
        ok = secp256k1_ec_seckey_verify(session->ctx, nonce32);
    }
    if (ok && session->entropy) {
        ok = secp256k1_ec_seckey_verify(session->ctx, session->entropy) &&
             secp256k1_ec_seckey_tweak_add(session->ctx, nonce32, session->entropy);
    }
    ae_clear(aux, sizeof(aux));
    ae_clear(preimage, sizeof(preimage));
    if (!ok) {
        ae_clear(nonce32, 32);
    }
    return ok;
}

int bitbox_anti_exfil_commit(
    const secp256k1_context* ctx,
    unsigned char nonce33[33],
    const unsigned char secret32[32],
    const unsigned char msg32[32],
    const unsigned char commitment32[32])
{
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pubkey;
    secp256k1_pubkey nonce;
    unsigned char normalized[32], xonly[32], scalar[32];
    int parity = 0;
    size_t len = 33;
    ae_nonce_data data = {ctx, commitment32, NULL};
    int ok = secp256k1_keypair_create(ctx, &keypair, secret32) &&
             secp256k1_keypair_xonly_pub(ctx, &pubkey, &parity, &keypair) &&
             secp256k1_xonly_pubkey_serialize(ctx, xonly, &pubkey);
    memcpy(normalized, secret32, 32);
    if (ok && parity) {
        ok = secp256k1_ec_seckey_negate(ctx, normalized);
    }
    if (ok) {
        ok = ae_nonce(
                 scalar,
                 msg32,
                 32,
                 normalized,
                 xonly,
                 (const unsigned char*)"BIP0340/nonce",
                 13,
                 &data) &&
             secp256k1_ec_pubkey_create(ctx, &nonce, scalar) &&
             secp256k1_ec_pubkey_serialize(ctx, nonce33, &len, &nonce, SECP256K1_EC_COMPRESSED);
    }
    ae_clear(normalized, sizeof(normalized));
    ae_clear(scalar, sizeof(scalar));
    ae_clear(&keypair, sizeof(keypair));
    if (!ok) {
        ae_clear(nonce33, 33);
    }
    return ok;
}

int bitbox_anti_exfil_sign(
    const secp256k1_context* ctx,
    unsigned char signature64[64],
    const unsigned char secret32[32],
    const unsigned char msg32[32],
    const unsigned char commitment32[32],
    const unsigned char nonce33[33],
    const unsigned char entropy32[32])
{
    unsigned char commitment[32], nonce[33];
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pubkey;
    ae_nonce_data data = {ctx, commitment32, entropy32};
    secp256k1_schnorrsig_extraparams params = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
    params.noncefp = ae_nonce;
    params.ndata = &data;
    int ok = secp256k1_ec_seckey_verify(ctx, entropy32) &&
             secp256k1_tagged_sha256(
                 ctx, commitment, (const unsigned char*)"BIP-EXFIL/host", 14, entropy32, 32) &&
             memcmp(commitment, commitment32, 32) == 0 &&
             bitbox_anti_exfil_commit(ctx, nonce, secret32, msg32, commitment32) &&
             memcmp(nonce, nonce33, 33) == 0 && secp256k1_keypair_create(ctx, &keypair, secret32) &&
             secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair) &&
             secp256k1_schnorrsig_sign_custom(ctx, signature64, msg32, 32, &keypair, &params) &&
             secp256k1_schnorrsig_verify(ctx, signature64, msg32, 32, &pubkey);
    ae_clear(&keypair, sizeof(keypair));
    if (!ok) {
        ae_clear(signature64, 64);
    }
    return ok;
}
