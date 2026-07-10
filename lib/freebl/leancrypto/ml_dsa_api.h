#ifndef ML_DSA_API_H
#define ML_DSA_API_H
// This is a generated file from the various XXX_sign.h files
#include <stddef.h>
#include "ml_dsa_apit.h"

// from ml_dsa_44_sign.h
int lc_dilithium_44_keypair_from_seed_c(struct lc_dilithium_44_pk *pk,
                                        struct lc_dilithium_44_sk *sk,
                                        const uint8_t *seed, size_t seedlen);

int lc_dilithium_44_sign_init_c(struct lc_dilithium_ctx *ctx,
                                const struct lc_dilithium_44_sk *sk);
int lc_dilithium_44_sign_update_c(struct lc_dilithium_ctx *ctx, const uint8_t *m,
                                  size_t mlen);
int lc_dilithium_44_sign_final_c(struct lc_dilithium_44_sig *sig,
                                 struct lc_dilithium_ctx *ctx,
                                 const struct lc_dilithium_44_sk *sk,
                                 struct lc_rng_ctx *rng_ctx);

int lc_dilithium_44_verify_init_c(struct lc_dilithium_ctx *ctx,
                                  const struct lc_dilithium_44_pk *pk);
int lc_dilithium_44_verify_update_c(struct lc_dilithium_ctx *ctx, const uint8_t *m,
                                    size_t mlen);
int lc_dilithium_44_verify_final_c(const struct lc_dilithium_44_sig *sig,
                                   struct lc_dilithium_ctx *ctx,
                                   const struct lc_dilithium_44_pk *pk);

// from ml_dsa_65_sign.h
int lc_dilithium_65_keypair_from_seed_c(struct lc_dilithium_65_pk *pk,
                                        struct lc_dilithium_65_sk *sk,
                                        const uint8_t *seed, size_t seedlen);

int lc_dilithium_65_sign_init_c(struct lc_dilithium_ctx *ctx,
                                const struct lc_dilithium_65_sk *sk);
int lc_dilithium_65_sign_update_c(struct lc_dilithium_ctx *ctx, const uint8_t *m,
                                  size_t mlen);
int lc_dilithium_65_sign_final_c(struct lc_dilithium_65_sig *sig,
                                 struct lc_dilithium_ctx *ctx,
                                 const struct lc_dilithium_65_sk *sk,
                                 struct lc_rng_ctx *rng_ctx);

int lc_dilithium_65_verify_init_c(struct lc_dilithium_ctx *ctx,
                                  const struct lc_dilithium_65_pk *pk);
int lc_dilithium_65_verify_update_c(struct lc_dilithium_ctx *ctx, const uint8_t *m,
                                    size_t mlen);
int lc_dilithium_65_verify_final_c(const struct lc_dilithium_65_sig *sig,
                                   struct lc_dilithium_ctx *ctx,
                                   const struct lc_dilithium_65_pk *pk);
// from ml_dsa_87_sign.h
int lc_dilithium_87_keypair_from_seed_c(struct lc_dilithium_87_pk *pk,
                                        struct lc_dilithium_87_sk *sk,
                                        const uint8_t *seed, size_t seedlen);

int lc_dilithium_87_sign_init_c(struct lc_dilithium_ctx *ctx,
                                const struct lc_dilithium_87_sk *sk);
int lc_dilithium_87_sign_update_c(struct lc_dilithium_ctx *ctx, const uint8_t *m,
                                  size_t mlen);
int lc_dilithium_87_sign_final_c(struct lc_dilithium_87_sig *sig,
                                 struct lc_dilithium_ctx *ctx,
                                 const struct lc_dilithium_87_sk *sk,
                                 struct lc_rng_ctx *rng_ctx);

int lc_dilithium_87_verify_init_c(struct lc_dilithium_ctx *ctx,
                                  const struct lc_dilithium_87_pk *pk);
int lc_dilithium_87_verify_update_c(struct lc_dilithium_ctx *ctx, const uint8_t *m,
                                    size_t mlen);
int lc_dilithium_87_verify_final_c(const struct lc_dilithium_87_sig *sig,
                                   struct lc_dilithium_ctx *ctx,
                                   const struct lc_dilithium_87_pk *pk);
#endif /* ML_DSA_API_H */
