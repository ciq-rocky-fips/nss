// SPDX-License-Identifier: MIT
// NSS SHA3 bindings for ML-DSA liboqs

#ifndef FIPS202_H
#define FIPS202_H

#include <blapi.h>

#define SHAKE128_RATE 168
#define shake128 SHAKE_128_HashBuf

#define SHAKE256_RATE SHA3_256_BLOCK_LENGTH
#define shake256 SHAKE_256_HashBuf

#ifdef NOT_SUPPORTED
#define SHA3_256_RATE SHA3_256_BLOCK_LENGTH
#define sha3_256 OQS_SHA3_sha3_256
#define sha3_256_inc_init OQS_SHA3_sha3_256_inc_init
#define sha3_256_inc_absorb OQS_SHA3_sha3_256_inc_absorb
#define sha3_256_inc_finalize OQS_SHA3_sha3_256_inc_finalize
#define sha3_256_inc_ctx_clone OQS_SHA3_sha3_256_inc_ctx_clone
#define sha3_256_inc_ctx_release OQS_SHA3_sha3_256_inc_ctx_release

#define SHA3_384_RATE SHA3_384_BLOCK_LENGTH
#define sha3_384 OQS_SHA3_sha3_384
#define sha3_384_inc_init OQS_SHA3_sha3_384_inc_init
#define sha3_384_inc_absorb OQS_SHA3_sha3_384_inc_absorb
#define sha3_384_inc_finalize OQS_SHA3_sha3_384_inc_finalize
#define sha3_384_inc_ctx_clone OQS_SHA3_sha3_384_inc_ctx_clone
#define sha3_384_inc_ctx_release OQS_SHA3_sha3_384_inc_ctx_release

#define SHA3_512_RATE SHA3_512_BLOCK_LENGTH
#define sha3_512 OQS_SHA3_sha3_512
#define sha3_512_inc_init OQS_SHA3_sha3_512_inc_init
#define sha3_512_inc_absorb OQS_SHA3_sha3_512_inc_absorb
#define sha3_512_inc_finalize OQS_SHA3_sha3_512_inc_finalize
#define sha3_512_inc_ctx_clone OQS_SHA3_sha3_512_inc_ctx_clone
#define sha3_512_inc_ctx_release OQS_SHA3_sha3_512_inc_ctx_release
#endif

typedef SHAKE_128Context *shake128incctx;
#define shake128_inc_init(ptr)         \
    (*(ptr)) = SHAKE_128_NewContext(); \
    SHAKE_128_Begin(*(ptr))
#define shake128_inc_absorb(ptr, input, inlen) SHAKE_128_Absorb(*(ptr), input, inlen)
#define shake128_inc_finalize(ptr)
#define shake128_inc_squeeze(output, outlen, ptr) SHAKE_128_SqueezeEnd(*(ptr), output, outlen)
#define shake128_inc_ctx_release(ptr) SHAKE_128_DestroyContext(*(ptr), PR_TRUE)
#define shake128_inc_ctx_reset(ptr) SHAKE_128_Begin(ptr)
#ifdef NOT_SUPPORTED
#define shake128_inc_ctx_clone OQS_SHA3_shake128_inc_ctx_clone
#endif

typedef SHAKE_256Context *shake256incctx;
#define shake256_inc_init(ptr)         \
    (*(ptr)) = SHAKE_256_NewContext(); \
    SHAKE_256_Begin(*(ptr))
#define shake256_inc_absorb(ptr, input, inlen) SHAKE_256_Absorb(*(ptr), input, inlen)
#define shake256_inc_finalize(ptr)
#define shake256_inc_squeeze(output, outlen, ptr) SHAKE_256_SqueezeEnd(*(ptr), output, outlen)
#define shake256_inc_ctx_release(ptr) SHAKE_256_DestroyContext(*(ptr), PR_TRUE)
#define shake256_inc_ctx_reset(ptr) SHAKE_256_Begin(*ptr)

#ifdef NOT_SUPPORTED
#define shake128_absorb_once OQS_SHA3_shake128_absorb_once
void OQS_SHA3_shake128_absorb_once(shake128incctx *state, const uint8_t *in, size_t inlen);

#define shake256_absorb_once OQS_SHA3_shake256_absorb_once
void OQS_SHA3_shake256_absorb_once(shake256incctx *state, const uint8_t *in, size_t inlen);
#endif

#define shake128_squeezeblocks(OUT, NBLOCKS, STATE) shake128_inc_squeeze(OUT, (NBLOCKS)*SHAKE128_RATE, STATE)

#define shake256_squeezeblocks(OUT, NBLOCKS, STATE) shake256_inc_squeeze(OUT, (NBLOCKS)*SHAKE256_RATE, STATE)

#endif
