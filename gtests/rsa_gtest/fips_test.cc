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

class FIPSRSAKeyTest : public ::testing::Test {};

// Encrypt an ephemeral RSA key
TEST_F(FIPSRSAKeyTest, GenRsaKey) {
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

  PK11RSAGenParams rsa_param;
  rsa_param.keySizeInBits = 1024;
  rsa_param.pe = 65537L;

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

}  // namespace nss_test
