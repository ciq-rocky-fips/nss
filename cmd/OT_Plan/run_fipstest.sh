
export build_dir=Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ

export LD_PRELOAD="/mnt/code/8.6/builder/nss/gh-nss/lib/smime/${build_dir}/libsmime3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/sysinit/${build_dir}/libnsssysinit.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/util/${build_dir}/libnssutil3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/softoken/legacydb/${build_dir}/libnssdbm3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/softoken/${build_dir}/libsoftokn3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/nss/${build_dir}/libnss3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/freebl/${build_dir}/Linux_SINGLE_SHLIB/libfreeblpriv3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/freebl/${build_dir}/Linux_SINGLE_SHLIB/libfreebl3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/ckfw/builtins/testlib/${build_dir}/libnssckbi-testlib.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/ckfw/builtins/${build_dir}/libnssckbi.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/ssl/${build_dir}/libssl3.so \
/mnt/code/8.6/builder/nss/gh-nss/gtests/pkcs11testmodule/${build_dir}/libpkcs11testmodule.so"


echo "set environment LD_PRELOAD /mnt/code/8.6/builder/nss/gh-nss/lib/smime/${build_dir}/libsmime3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/sysinit/${build_dir}/libnsssysinit.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/util/${build_dir}/libnssutil3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/softoken/legacydb/${build_dir}/libnssdbm3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/softoken/${build_dir}/libsoftokn3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/nss/${build_dir}/libnss3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/freebl/${build_dir}/Linux_SINGLE_SHLIB/libfreeblpriv3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/freebl/${build_dir}/Linux_SINGLE_SHLIB/libfreebl3.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/ckfw/builtins/testlib/${build_dir}/libnssckbi-testlib.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/ckfw/builtins/${build_dir}/libnssckbi.so \
/mnt/code/8.6/builder/nss/gh-nss/lib/ssl/${build_dir}/libssl3.so \
/mnt/code/8.6/builder/nss/gh-nss/gtests/pkcs11testmodule/${build_dir}/libpkcs11testmodule.so"


#gdb --args Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/pk11mode -v

if [ -f "key4.db" ]; then
    rm "key4.db"
fi

if [ -f "cert9.db" ]; then
   rm "cert9.db"
fi

fips-mode-setup --check

export NSS_ENABLE_AUDIT=1
echo "i. Set the environment variable NSS_ENABLE_AUDIT to ‘1’ before using the module with an application."
echo "NSS_ENABLE_AUDIT=$NSS_ENABLE_AUDIT"

#gdb Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/pk11mode
#Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/pk11mode -v

Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/pk11mode -v > 42.log

echo "Get function list - FC_GetFunctionList"
echo "[`grep -n C_GetFunctionList 42.log | wc -l`]"
echo "Initialize token - FC_InitToken"
echo "[`grep -n C_InitToken 42.log | wc -l`]"
echo "Initialize the User password - FC_InitPIN"
echo "[`grep -n C_InitPIN 42.log | wc -l`]"
echo "Initialize the module  - FC_Initialize"
echo "[`grep -n C_Initialize 42.log | wc -l`]"
echo "Finalize the module - FC_Finalize"
echo "[`grep -n C_Finalize 42.log | wc -l`]"
echo "Get general module information - FC_GetInfo"
echo "[`grep -n C_GetInfo 42.log | wc -l`]"
echo "Get slot list - FC_GetSlotList"
echo "[`grep -n C_GetSlotList 42.log | wc -l`]"
echo "Get slot info - FC_GetSlotInfo"
echo "[`grep -n C_GetSlotInfo 42.log | wc -l`]"
echo "Get token info - FC_GetTokenInfo"
echo "[`grep -n C_GetTokenInfo 42.log | wc -l`]"
echo "Get mechanism list - FC_GetMechanismList"
echo "[`grep -n C_GetMechanismList 42.log | wc -l`]"
echo "Get mechanism info - FC_GetMechanismInfo"
echo "[`grep -n C_GetMechanismInfo 42.log | wc -l`]"
echo "Set PIN - FC_SetPIN"
echo "[`grep -n C_SetPIN 42.log | wc -l`]"
echo "Open session - FC_OpenSession"
echo "[`grep -n C_OpenSession 42.log | wc -l`]"
echo "Close session - FC_CloseSession"
echo "[`grep -n C_CloseSession 42.log | wc -l`]"
echo "Close all sessions - FC_CloseAllSessions"
echo "[`grep -n C_CloseAllSessions 42.log | wc -l`]"
echo "Get session info - FC_GetSessionInfo"
echo "[`grep -n C_GetSessionInfo 42.log | wc -l`]"
echo "Get operation state - FC_GetOperationState"
echo "[`grep -n C_GetOperationState 42.log | wc -l`]"
echo "Set operation state - FC_SetOperationState"
echo "[`grep -n C_SetOperationState 42.log | wc -l`]"
echo "Login - FC_Login"
echo "[`grep -n C_Login 42.log | wc -l`]"
echo "Logout - FC_Logout"
echo "[`grep -n C_Logout 42.log | wc -l`]"
echo "Create object - FC_CreateObject"
echo "[`grep -n C_CreateObject 42.log | wc -l`]"
echo "Copy object - FC_CopyObject"
echo "[`grep -n C_CopyObject 42.log | wc -l`]"
echo "Destroy object - FC_DestroyObject"
echo "[`grep -n C_DestroyObject 42.log | wc -l`]"
echo "Get object size - FC_GetObjectSize"
echo "[`grep -n C_GetObjectSize 42.log | wc -l`]"
echo "Get attribute value - FC_GetAttributeValue"
echo "[`grep -n C_GetAttributeValue 42.log | wc -l`]"
echo "Set attribute value - FC_SetAttributeValue"
echo "[`grep -n C_SetAttributeValue 42.log | wc -l`]"
echo "Find objects initialize - FC_FindObjectsInit"
echo "[`grep -n C_FindObjectsInit 42.log | wc -l`]"
echo "Find object - FC_FindObjects"
echo "[`grep -n C_FindObjects 42.log | wc -l`]"
echo "Find objects finalize - FC_FindObjectsFinal"
echo "[`grep -n C_FindObjectsFinal 42.log | wc -l`]"
echo "Encrypt initialize - FC_EncryptInit"
echo "[`grep -n C_EncryptInit 42.log | wc -l`]"
echo "Encrypt - FC_Encrypt"
echo "[`grep -n C_Encrypt 42.log | wc -l`]"
echo "Encrypt update - FC_Encrypt"
echo "[`grep -n C_Encrypt 42.log | wc -l`]"
echo "Encrypt final - FC_EncryptFinal"
echo "[`grep -n C_EncryptFinal 42.log | wc -l`]"
echo "Decrypt initialize - FC_DecryptInit "
echo "[`grep -n C_DecryptInit 42.log | wc -l`]"
echo "Decrypt - FC_Decrypt"
echo "[`grep -n C_Decrypt 42.log | wc -l`]"
echo "Decrypt update - FC_DecryptUpdate"
echo "[`grep -n C_DecryptUpdate 42.log | wc -l`]"
echo "Decrypt final - FC_DecryptFinal"
echo "[`grep -n C_DecryptFinal 42.log | wc -l`]"
echo "Digest initialize - FC_DigestInit"
echo "[`grep -n C_DigestInit 42.log | wc -l`]"
echo "Digest - FC_Digest"
echo "[`grep -n C_Digest 42.log | wc -l`]"
echo "Digest update - FC_DigestUpdate"
echo "[`grep -n C_DigestUpdate 42.log | wc -l`]"
echo "Digest key - FC_DigestKey"
echo "[`grep -n C_DigestKey 42.log | wc -l`]"
echo "Digest finalize - FC_DigestFinal"
echo "[`grep -n C_DigestFinal 42.log | wc -l`]"
echo "Sign initialize - FC_SignInit"
echo "[`grep -n C_SignInit 42.log | wc -l`]"
echo "Sign - FC_Sign"
echo "[`grep -n C_Sign 42.log | wc -l`]"
echo "Sign update - FC_SignUpdate"
echo "[`grep -n C_SignUpdate 42.log | wc -l`]"
echo "Sign final - FC_SignFinal"
echo "[`grep -n C_SignFinal 42.log | wc -l`]"
echo "Sign/recover initialize - FC_SignRecoverInit"
echo "[`grep -n C_SignRecoverInit 42.log | wc -l`]"
echo "Sign/recover - FC_SignRecover"
echo "[`grep -n C_SignRecover 42.log | wc -l`]"
echo "Verify initialize - FC_VerifyInit"
echo "[`grep -n C_VerifyInit 42.log | wc -l`]"
echo "Verify - FC_Verify"
echo "[`grep -n C_Verify 42.log | wc -l`]"
echo "Verify update - FC_VerifyUpdate"
echo "[`grep -n C_VerifyUpdate 42.log | wc -l`]"
echo "Verify final - FC_VerifyFinal"
echo "[`grep -n C_VerifyFinal 42.log | wc -l`]"
echo "Verify/recover initialize - FC_VerifyRecoverInit"
echo "[`grep -n C_VerifyRecoverInit 42.log | wc -l`]"
echo "Verify/recover - FC_VerifyRecover"
echo "[`grep -n C_VerifyRecover 42.log | wc -l`]"
echo "Digest/encrypt update - FC_DigestEncryptUpdate"
echo "[`grep -n C_DigestEncryptUpdate 42.log | wc -l`]"
echo "Decrypt/digest update - FC_DecryptDigestUpdate"
echo "[`grep -n C_DecryptDigestUpdate 42.log | wc -l`]"
echo "Sign/encrypt update - FC_SignEncryptUpdate"
echo "[`grep -n C_SignEncryptUpdate 42.log | wc -l`]"
echo "Decrypt/verify update - FC_DecryptVerifyUpdate"
echo "[`grep -n C_DecryptVerifyUpdate 42.log | wc -l`]"
echo "Generate secret key - FC_GenerateKey"
echo "[`grep -n C_GenerateKey 42.log | wc -l`]"
echo "Generate key pair - FC_GenerateKeyPair"
echo "Wrap key - FC_WrapKey"
echo "[`grep -n C_WrapKey 42.log | wc -l`]"
echo "Unwrap key - FC_UnwrapKey"
echo "[`grep -n C_UnwrapKey 42.log | wc -l`]"
echo "Derive key - FC_DeriveKey"
echo "[`grep -n C_DeriveKey 42.log | wc -l`]"
echo "Seed DRBG - FC_SeedRandom"
echo "[`grep -n C_SeedRandom 42.log | wc -l`]"
echo "Generate random number - FC_GenerateRandom"
echo "[`grep -n C_GenerateRandom 42.log | wc -l`]"
echo "Perform self-tests"
echo "[`grep -n C_ 42.log | wc -l`]"
echo "Show status"
echo "[`grep -n C_ 42.log | wc -l`]"
echo "Show versioning information"
echo "[`grep -n C_ 42.log | wc -l`]"
echo "Zeroize – destroy object"
echo "[`grep -n C_ 42.log | wc -l`]"

#ldd Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/pk11mode
