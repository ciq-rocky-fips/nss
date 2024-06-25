/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <memory>
#include "gtest/gtest.h"
#include "nss.h"
#include "nss_scoped_ptrs.h"
#include "pk11pub.h"
#include "prerror.h"
#include "secmod.h"
#include "secerr.h"
#include "util.h"

namespace nss_test {

class FIPSKeyTest : public ::testing::Test {};

// Encrypt an ephemeral EC key (U2F use case)
TEST_F(FIPSKeyTest, GenECKey) {  
  const uint32_t kOidLen = 65;
  unsigned char param_buf[kOidLen];  
  char *internal_name;
  if (!PK11_IsFIPS())  {
    internal_name = PR_smprintf("%s", SECMOD_GetInternalModule()->commonName);
    ASSERT_EQ(SECSuccess, SECMOD_DeleteInternalModule(internal_name))
        << PORT_ErrorToName(PORT_GetError());
    PR_smprintf_free(internal_name);
    ASSERT_TRUE(PK11_IsFIPS());
  }

  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  ASSERT_NE(nullptr, slot);

  SECItem ecdsa_params = {siBuffer, param_buf, sizeof(param_buf)};
  SECOidData* oid_data = SECOID_FindOIDByTag(SEC_OID_SECG_EC_SECP256R1);
  ASSERT_NE(oid_data, nullptr);
  ecdsa_params.data[0] = SEC_ASN1_OBJECT_ID;
  ecdsa_params.data[1] = oid_data->oid.len;
  memcpy(ecdsa_params.data + 2, oid_data->oid.data, oid_data->oid.len);
  ecdsa_params.len = oid_data->oid.len + 2;

  SECKEYPublicKey* pub_tmp;
  ScopedSECKEYPublicKey pub_key;
  ScopedSECKEYPrivateKey priv_key(
      PK11_GenerateKeyPair(slot.get(), CKM_EC_KEY_PAIR_GEN, &ecdsa_params,
                           &pub_tmp, PR_FALSE, PR_TRUE, nullptr));
  ASSERT_NE(nullptr, priv_key) << PORT_ErrorToName(PORT_GetError());
  ASSERT_NE(nullptr, pub_tmp);
  pub_key.reset(pub_tmp);
  PORT_SetError(0);
}

// Encrypt an ephemeral RSA key
TEST_F(FIPSKeyTest, GenRsaKey) {
  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  ASSERT_NE(nullptr, slot);

  PK11RSAGenParams rsa_param;
  rsa_param.keySizeInBits = 4096;
  rsa_param.pe = 0x10001;

  SECKEYPublicKey* pub_tmp;
  ScopedSECKEYPublicKey pub_key;
  ScopedSECKEYPrivateKey priv_key(
      PK11_GenerateKeyPair(slot.get(), CKM_RSA_PKCS_KEY_PAIR_GEN, &rsa_param,
                           &pub_tmp, PR_FALSE, PR_TRUE, nullptr));
  ASSERT_NE(nullptr, priv_key) << PORT_ErrorToName(PORT_GetError());
  ASSERT_NE(nullptr, pub_tmp);
  pub_key.reset(pub_tmp);
  PORT_SetError(0);
}

// Generated with "openssl dsaparam -C -noout 2048" and reformatted.
// openssl 1.0 or later must be used so that a 256-bit Q value is
// generated.
static const uint8_t DSS_P_RAW[] =
{
  0xB3,0xCD,0x29,0x44,0xF0,0x25,0xA7,0x73,0xFC,0x86,0x70,0xA2,
  0x69,0x5A,0x97,0x3F,0xBD,0x1C,0x6F,0xAA,0x4A,0x40,0x42,0x8E,
  0xCF,0xAE,0x62,0x12,0xED,0xB4,0xFD,0x05,0xC2,0xAE,0xB1,0x8C,
  0xFC,0xBE,0x38,0x90,0xBB,0x7C,0xFF,0x16,0xF4,0xED,0xCE,0x72,
  0x12,0x93,0x83,0xF0,0xA4,0xA1,0x71,0xDC,0x4B,0xF0,0x4E,0x3A,
  0x2B,0xFA,0x17,0xB7,0xB3,0x2A,0xCC,0x2C,0xD3,0xC8,0x21,0x49,
  0x7A,0x83,0x71,0x8B,0x3D,0x62,0x96,0xDC,0xAD,0xA8,0x03,0xBE,
  0x1D,0x33,0x11,0xF3,0xEB,0xD8,0x1B,0x8D,0xDB,0x62,0x79,0x83,
  0xF8,0x67,0x4E,0x62,0x21,0x2C,0x81,0x59,0xE8,0x73,0xD7,0xAF,
  0xB9,0x63,0x60,0xEA,0xAE,0xEC,0x68,0x6A,0xB4,0xB0,0x65,0xBA,
  0xA3,0x4C,0x09,0x99,0x29,0x6A,0x2E,0x2B,0xFC,0x6D,0x51,0xCA,
  0x30,0xA2,0x2F,0x7A,0x65,0x76,0xA7,0x55,0x13,0x11,0xA0,0x02,
  0xA2,0x59,0x4B,0xCE,0xA7,0x05,0xF6,0x07,0x35,0x9B,0x41,0xD7,
  0x11,0x5A,0x18,0x57,0xA7,0x78,0x88,0xC3,0xA8,0xE3,0x39,0xF5,
  0x47,0x3D,0x2E,0x18,0x54,0xB0,0xF0,0xBF,0x65,0x3F,0x77,0xC7,
  0x11,0xB8,0x0D,0x52,0xAD,0xC8,0xE8,0x6D,0xF6,0x7E,0x88,0x65,
  0x84,0x2B,0xF7,0xEF,0x8E,0xB5,0x7C,0xBD,0x2E,0x0D,0xF3,0xC6,
  0xDD,0x0B,0xB4,0xF2,0x23,0x1F,0xDA,0x55,0x05,0xF5,0xDC,0x53,
  0xA6,0x83,0xDA,0x5C,0xEF,0x29,0x02,0x78,0x68,0xD0,0xA4,0x39,
  0x09,0x7F,0xFA,0x49,0x18,0xD0,0xB5,0x19,0x35,0x31,0x8E,0xDE,
  0x43,0x35,0xA3,0xB9,0x6D,0xC1,0x70,0xC6,0x0D,0x18,0x24,0xEB,
  0x1E,0x4D,0x52,0xB7,
};

static const uint8_t DSS_Q_RAW[] =
{
  0x8D,0x6B,0x86,0x89,0x9C,0x8D,0x30,0x91,0xCC,0x6E,0x34,0xF1,
  0xE8,0x9C,0x8A,0x5C,0xD6,0xAB,0x01,0x1E,0xC4,0xDB,0xFD,0x07,
  0xEB,0x5F,0x4E,0xE8,0xFA,0xFC,0x98,0x2D,
};

static const uint8_t DSS_G_RAW[] =
{
  0x0E,0x2C,0x34,0xB2,0xE1,0x66,0x49,0xB6,0x9A,0x7D,0x67,0x3E,
  0xEE,0x98,0x35,0x18,0x28,0x35,0xFC,0x05,0x36,0x3B,0x94,0xE6,
  0x1E,0x1C,0x5B,0x05,0x3E,0x86,0x1B,0xE3,0xED,0xD2,0xE1,0xF3,
  0xF7,0xF7,0x60,0x6D,0x7D,0xA1,0xAF,0x9A,0xD1,0xDF,0xA2,0x9C,
  0xFC,0xA2,0xEB,0x90,0x8B,0x1C,0x82,0x92,0x45,0x7B,0x30,0x2A,
  0xFD,0x7A,0xE6,0x68,0x8F,0xEC,0x89,0x3A,0x9A,0xAD,0xFE,0x25,
  0x5E,0x51,0xC5,0x29,0x45,0x7F,0xAC,0xDE,0xFC,0xB4,0x1B,0x3A,
  0xDA,0xC7,0x21,0x68,0x87,0x27,0x8D,0x7B,0xB2,0xBB,0x41,0x60,
  0x46,0x42,0x5B,0x6B,0xE8,0x80,0xD2,0xE4,0xA3,0x30,0x8F,0xD5,
  0x71,0x07,0x8A,0x7B,0x32,0x56,0x84,0x41,0x1C,0xDF,0x69,0xE9,
  0xFD,0xBA,0x48,0xE0,0x43,0xA0,0x38,0x92,0x12,0xF3,0x52,0xA5,
  0x40,0x87,0xCB,0x34,0xBB,0x3E,0x25,0x29,0x3C,0xC6,0xA5,0x17,
  0xFD,0x58,0x47,0x89,0xDB,0x9B,0xB9,0xCF,0xE9,0xA8,0xF2,0xEC,
  0x55,0x76,0xF5,0xF1,0x9C,0x6E,0x0A,0x3F,0x16,0x5F,0x49,0x31,
  0x31,0x1C,0x43,0xA2,0x83,0xDA,0xDD,0x7F,0x1C,0xEA,0x05,0x36,
  0x7B,0xED,0x09,0xFB,0x6F,0x8A,0x2B,0x55,0xB9,0xBC,0x4A,0x8C,
  0x28,0xC1,0x4D,0x13,0x6E,0x47,0xF4,0xAD,0x79,0x00,0xE9,0x5A,
  0xB6,0xC7,0x73,0x28,0xA9,0x89,0xAD,0xE8,0x6E,0xC6,0x54,0xA5,
  0x56,0x2D,0xAA,0x81,0x83,0x9E,0xC1,0x13,0x79,0xA4,0x12,0xE0,
  0x76,0x1F,0x25,0x43,0xB6,0xDE,0x56,0xF7,0x52,0xCC,0x07,0xB8,
  0x37,0xE2,0x8C,0xC5,0x56,0x8C,0xDD,0x63,0xF5,0xB6,0xA3,0x46,
  0x62,0xF6,0x35,0x76,
};

// from: BUILD/nss-3.79/nss/gtests/softoken_gtest/softoken_dh_vectors.h
/* IKE 2048 prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 } */
static const unsigned char prime_ike_2048[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
    0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
    0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF};

static const unsigned char g2[] = {2};

// Gen DH key
TEST_F(FIPSKeyTest, GenDhKey) {
  SECItem lp = {siBuffer, (unsigned char *)prime_ike_2048, sizeof(prime_ike_2048)};
  SECItem lg = {siBuffer, (unsigned char *)g2, sizeof(g2)};
  
  SECKEYDHParams dh_params;
  dh_params.base = lg;
  dh_params.prime = lp;
      
  ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
  EXPECT_TRUE(slot);
    
  /* create a private/public key pair in with the given params */
  SECKEYPublicKey *pub_tmp = nullptr;
  ScopedSECKEYPublicKey pub_key;
  ScopedSECKEYPrivateKey priv_key(
      PK11_GenerateKeyPair(slot.get(), CKM_DH_PKCS_KEY_PAIR_GEN, &dh_params,
                           &pub_tmp, PR_FALSE, PR_TRUE, nullptr));
  EXPECT_NE(nullptr, priv_key.get()) << "PK11_GenerateKeyPair failed: "
                                     << PORT_ErrorToName(PORT_GetError());
  ASSERT_NE(nullptr, pub_tmp);
  pub_key.reset(pub_tmp);
  PORT_SetError(0);
  }
}  // namespace nss_test
