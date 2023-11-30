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

class FIPSECKeyTest : public ::testing::Test {};

// Encrypt an ephemeral EC key (U2F use case)
TEST_F(FIPSECKeyTest, GenECKey) {  
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


}  // namespace nss_test
