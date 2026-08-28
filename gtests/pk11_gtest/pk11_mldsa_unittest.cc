/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <memory>
#include "nss.h"
#include "prerror.h"
#include "pk11pub.h"
#include "sechash.h"
#include "cryptohi.h"

#include "cpputil.h"
#include "databuffer.h"
#include "pk11_signature_test.h"

#include "gtest/gtest.h"
#include "nss_scoped_ptrs.h"

#include "testvectors/ml-dsa-verify-vectors.h"
#include "testvectors/ml-dsa-keygen-vectors.h"
#include "ml-dsa-ietf-vectors.h"

namespace nss_test {

class Pkcs11MlDsaTestBase : public Pk11SignatureTest {
 private:
  DataBuffer sig_ctx;
  CK_SIGN_ADDITIONAL_CONTEXT mldsa_params_;
  SECItem params_;
  bool params_valid_;

 protected:
  Pkcs11MlDsaTestBase(void)
      : Pk11SignatureTest(CKM_ML_DSA, SEC_OID_UNKNOWN, CKM_ML_DSA) {
    params_.data = NULL;
    params_.len = 0;
    params_valid_ = false;
  }

  const SECItem *parameters() const {
    if (!params_valid_) return NULL;
    return &params_;
  }
  void setParams(CK_HEDGE_TYPE hedgeType, const DataBuffer &ctx) {
    sig_ctx = ctx;
    mldsa_params_.hedgeVariant = hedgeType;
    mldsa_params_.pContext = sig_ctx.data();
    mldsa_params_.ulContextLen = sig_ctx.len();
    params_.data = reinterpret_cast<unsigned char *>(&mldsa_params_);
    params_.len = sizeof(mldsa_params_);
    params_valid_ = true;
  }
  void clearParams(void) { params_valid_ = false; }
  const char *get_param_set(SECKEYPublicKey *key) const {
    if (key->keyType != mldsaKey) {
      return "Not-ml-dsa";
    }
    const char *result = SECOID_FindOIDTagDescription(key->u.mldsa.paramSet);
    if (result == NULL) {
      return "Unknown";
    }
    return result;
  }
  void Verify(const MlDsaVerifyTestVector vec) {
    /* DSA vectors encode the signature in DER, we need to unwrap it before
     * we can send the raw signatures to PKCS #11. */
    DataBuffer pubKeyBuffer(vec.public_key.data(), vec.public_key.size());
    ScopedSECKEYPublicKey nssPubKey(ImportPublicKey(pubKeyBuffer));
    SECItem sigItem = {siBuffer, toUcharPtr(vec.sig.data()),
                       static_cast<unsigned int>(vec.sig.size())};
    Pkcs11SignatureTestParams params = {
        DataBuffer(), pubKeyBuffer, DataBuffer(vec.msg.data(), vec.msg.size()),
        DataBuffer(sigItem.data, sigItem.len)};
    std::cout << "MLDSA Vec " << vec.id << ": ";
    std::cout << get_param_set(nssPubKey.get()) << " ";
    std::cout << "key(" << vec.public_key.size() << ") ";
    std::cout << "message(" << vec.msg.size() << ") ";
    std::cout << "signature(" << sigItem.len << ") ";
    std::cout << "ctx(" << vec.ctx.size() << ") " << std::endl;
    params_.len = 0;
    if (vec.ctx.size() != 0) {
      setParams(CKH_HEDGE_PREFERRED,
                DataBuffer(vec.ctx.data(), vec.ctx.size()));
    }
    Pk11SignatureTest::Verify(params, (bool)vec.valid);
  }
  void ImportAndSignAndVerify(const MlDsaTestVector vec) {
    DataBuffer privKeyBuffer(vec.private_key.data(), vec.private_key.size());
    DataBuffer pubKeyBuffer(vec.public_key.data(), vec.public_key.size());
    DataBuffer message(vec.msg.data(), vec.msg.size());
    DataBuffer sig, sig2;
    if ((vec.ctx.size() == 0) && (vec.hedgeType == CKH_HEDGE_PREFERRED)) {
      clearParams();
    } else {
      setParams(vec.hedgeType, DataBuffer(vec.ctx.data(), vec.ctx.size()));
    }
    Pk11SignatureTest::ImportPrivateKeyAndSignHashedData(privKeyBuffer, message,
                                                         &sig, &sig2);
    Pkcs11SignatureTestParams params = {DataBuffer(), pubKeyBuffer, message,
                                        sig};
    Pk11SignatureTest::Verify(params, true);
  }
  void KeyGenFromSeed(const MlDsaKeyGenTestVector vec) {
    CK_OBJECT_CLASS private_key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ml_dsa_key_type = CKK_ML_DSA;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    unsigned char id_val[] = {0x00, 0x01, 0x02, 0x03};
    // let's us find the key so we can get a SECKEYPrivateKey object
    SECItem key_id = {siBuffer, id_val, sizeof(id_val)};
    CK_ATTRIBUTE pk11Template[] = {
        {CKA_CLASS, &private_key_class, sizeof(private_key_class)},
        {CKA_KEY_TYPE, &ml_dsa_key_type, sizeof(ml_dsa_key_type)},
        {CKA_TOKEN, &ck_false, sizeof(ck_false)},
        {CKA_EXTRACTABLE, &ck_true, sizeof(ck_false)},
        {CKA_SENSITIVE, &ck_false, sizeof(ck_false)},
        {CKA_PARAMETER_SET, (CK_VOID_PTR)(&vec.param_set),
         sizeof(vec.param_set)},
        {CKA_ID, key_id.data, key_id.len},
        {CKA_SEED, (CK_VOID_PTR)(vec.seed.data()), vec.seed.size()},
    };
    CK_ULONG pk11TemplateCount = PR_ARRAY_SIZE(pk11Template);

    /* import the key as a seed. This will force an internal KEYGEN,
     * to calculate CKA_VALUE */
    ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
    /* ScopedCK_OBJECT_HANDLE privKeyID(slot.get()); */
    ScopedPK11GenericObject genPrivKey(PK11_CreateManagedGenericObject(
        slot.get(), pk11Template, pk11TemplateCount, PR_FALSE));
    if (genPrivKey == nullptr) {
      ADD_FAILURE() << "Couldn't create key from seed\n"
                    << "Error: " << PORT_ErrorToString(PORT_GetError());
      return;
    }

    /* Fetch the CKA_VALUE and compare with our private key */
    ScopedSECItem privKeyValue(PORT_ZNew(SECItem));
    SECStatus rv = PK11_ReadRawAttribute(PK11_TypeGeneric, genPrivKey.get(),
                                         CKA_VALUE, privKeyValue.get());
    if (rv != SECSuccess) {
      ADD_FAILURE() << "Couldn't read private key value\n"
                    << "Error: " << PORT_ErrorToString(PORT_GetError());
      return;
    }
    ASSERT_EQ(privKeyValue->len, vec.private_key.size());
    ASSERT_TRUE(PORT_Memcmp(privKeyValue->data, vec.private_key.data(),
                            privKeyValue->len) == 0);

    /* now get the pubickey.. this will generate another KEYGEN! */
    ScopedSECKEYPrivateKey privKey(
        PK11_FindKeyByKeyID(slot.get(), &key_id, NULL));
    ASSERT_NE(privKey, nullptr)
        << "Error: " << PORT_ErrorToString(PORT_GetError());
    ScopedSECKEYPublicKey pubKey(SECKEY_ConvertToPublicKey(privKey.get()));
    ASSERT_NE(pubKey, nullptr)
        << "Error: " << PORT_ErrorToString(PORT_GetError());

    /* Fetch the CKA_VALUE and compare with our public key */
    ASSERT_EQ(pubKey->keyType, mldsaKey);
    ASSERT_EQ(pubKey->u.mldsa.publicValue.len, vec.public_key.size());
    ASSERT_TRUE(PORT_Memcmp(pubKey->u.mldsa.publicValue.data,
                            vec.public_key.data(), vec.public_key.size()) == 0);
  }
};
class Pkcs11MlDsaKeyGenTest
    : public Pkcs11MlDsaTestBase,
      public ::testing::WithParamInterface<MlDsaKeyGenTestVector> {
 public:
  Pkcs11MlDsaKeyGenTest() : Pkcs11MlDsaTestBase() {}
};

class Pkcs11MlDsaVerifyTest
    : public Pkcs11MlDsaTestBase,
      public ::testing::WithParamInterface<MlDsaVerifyTestVector> {
 public:
  Pkcs11MlDsaVerifyTest() : Pkcs11MlDsaTestBase() {}
};

class Pkcs11MlDsaTest : public Pkcs11MlDsaTestBase,
                        public ::testing::WithParamInterface<MlDsaTestVector> {
 public:
  Pkcs11MlDsaTest() : Pkcs11MlDsaTestBase() {}
};

TEST_P(Pkcs11MlDsaKeyGenTest, NISTKeygenTestsFromSeed) {
  KeyGenFromSeed(GetParam());
}

INSTANTIATE_TEST_SUITE_P(MlDsaTest, Pkcs11MlDsaKeyGenTest,
                         ::testing::ValuesIn(kMLDsaNISTKeyGenVectors));

TEST_P(Pkcs11MlDsaTest, ImportAndSignAndVerify) {
  ImportAndSignAndVerify(GetParam());
}

INSTANTIATE_TEST_SUITE_P(MlDsaTest, Pkcs11MlDsaTest,
                         ::testing::ValuesIn(kMlDsaTestVectors));

TEST_P(Pkcs11MlDsaVerifyTest, NISTACVPVectors) { Verify(GetParam()); }

INSTANTIATE_TEST_SUITE_P(MlDsaTest, Pkcs11MlDsaVerifyTest,
                         ::testing::ValuesIn(kMLDsaNISTVerifyVectors));

}  // namespace nss_test
