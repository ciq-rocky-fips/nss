#export NSS_FIPS_LOGGING="SYSLOG"
export NSS_FIPS_LOGGING="STDERR"
export NSS_FIPS_FUNC_TEST="FT"

rm -r ../ft
mkdir ../ft

declare -a StringArray=(\
":PRNGTEST_RunHealthTests.Instantiate" \
":PRNGTEST_RunHealthTests.Generate" \
":PRNGTEST_RunHealthTests.reseed" \
":PRNGTEST_RunHealthTests.no_reseed" \
":PRNGTEST_RunHealthTests.entropy_check" \
":PRNGTEST_RunHealthTests.Uninstantiate_check" \
":AES-ECB-ENCRYPT.128" \
":AES-ECB-DECRYPT.128" \
":AES-ECB-ENCRYPT.192" \
":AES-ECB-DECRYPT.192" \
":AES-ECB-ENCRYPT.256" \
":AES-ECB-DECRYPT.256" \
":AES-CBC-ENCRYPT.128" \
":AES-CBC-DECRYPT.128" \
":AES-CBC-ENCRYPT.192" \
":AES-CBC-DECRYPT.192" \
":AES-CBC-ENCRYPT.256" \
":AES-CBC-DECRYPT.256" \
":AES-GCM-ENCRYPT.128" \
":AES-GCM-DECRYPT.128" \
":AES-GCM-ENCRYPT.192" \
":AES-GCM-DECRYPT.192" \
":AES-GCM-ENCRYPT.256" \
":AES-GCM-DECRYPT.256" \
":AES-CMAC-GEN.128" \
":AES-CMAC-VERIFY.128" \
":AES-CMAC-GEN.192" \
":AES-CMAC-VERIFY.192" \
":AES-CMAC-GEN.256" \
":AES-CMAC-VERIFY.256" \
":RSA-SIGN.SHA256" \
":RSA-VERIFY.SHA256" \
":RSA-SIGN.SHA348" \
":RSA-VERIFY.SHA348" \
":RSA-SIGN.SHA512" \
":RSA-VERIFY.SHA512" \
":HMAC.SHA-1" \
":HMAC.SHA-224" \
":HMAC.SHA-256" \
":HMAC.SHA-384" \
":HMAC.SHA-512" \
":TLS_PRF.1.0" \
":TLS_12.SHA256" \
":TLS_12.SHA224" \
":TLS_12.SHA384" \
":TLS_12.SHA512" \
":SHA.1" \
":SHA.224" \
":SHA.265" \
":SHA.384" \
":SHA.512" \
":RSA-ENCRYPT.2048" \
":RSA-DECRYPT.2048" \
":ECDSA.SIG" \
":ECDSA.VERIFY" \
":ECDH.P-256" \
":DSA.SIGN" \
":DSA.VERIFY" \
":DH.COMPUT" \
":RNG.INTEG" \
":libfreeblpriv3.INTEG" \
":HKDF.SHA256" \
":HKDF.SHA384" \
":HKDF.SHA512" \
":INTEGRITY.softoken" \
":PBKDF2.SHA256" \
":IKE.KAT" \
":KBKDF.KAT" \
)

#export build_dir=Linux5.14_x86_64_cc_glibc_PTH_64_DBG.OBJ
export build_dir=Linux5.14_x86_64_cc_glibc_PTH_64_OPT.OBJ

export LD_PRELOAD="./lib/smime/${build_dir}/libsmime3.so \
./lib/sysinit/${build_dir}/libnsssysinit.so \
./lib/util/${build_dir}/libnssutil3.so \
./lib/softoken/legacydb/${build_dir}/libnssdbm3.so \
./lib/softoken/${build_dir}/libsoftokn3.so \
./lib/nss/${build_dir}/libnss3.so \
./lib/freebl/${build_dir}/Linux_SINGLE_SHLIB/libfreeblpriv3.so \
./lib/freebl/${build_dir}/Linux_SINGLE_SHLIB/libfreebl3.so \
./lib/ckfw/builtins/testlib/${build_dir}/libnssckbi-testlib.so \
./lib/ckfw/builtins/${build_dir}/libnssckbi.so \
./lib/ssl/${build_dir}/libssl3.so \
./gtests/pkcs11testmodule/${build_dir}/libpkcs11testmodule.so"

export INTEG_softokn="./lib/softoken/${build_dir}/libsoftokn3.so"
export INTEG_libfreeblpriv3="./lib/freebl/${build_dir}/Linux_SINGLE_SHLIB/libfreeblpriv3.so"

export NSS_DISABLE_HW_AES=1
export NSS_DISABLE_HW_SHA1=1
export NSS_DISABLE_HW_SHA2=1
export NSS_DISABLE_PCLMUL=1
export NSS_DISABLE_AVX=1
export NSS_DISABLE_ARM_NEON=1
export NSS_DISABLE_SSSE3=1

echo "HelpMedsfafasdjflj7897987" > /tmp/password_file.txt

echo "SUCCESS CASE"
echo ../ft/SUCCESS_POST.log
#./cmd/certutil/${build_dir}/certutil -N -d . -f /tmp/password_file.txt &> ../ft/SUCCESS_POST.log
./cmd/certutil/${build_dir}/certutil -U &> ../ft/SUCCESS_POST.log
#gdb --args cmd/fipstest/${build_dir}/fipstest
grep -n "FAILED" ../ft/SUCCESS_POST.log 2> /dev/null
echo "*****************"

for val in ${StringArray[@]}; do
  myString="${val:1}"  
  export NSS_FIPS_FUNC_TEST_NAMES=$myString  
  echo "INDUCE FAILURE"
  echo ../ft/$myString.log    
    #./cmd/certutil/${build_dir}/certutil -N -d . -f /tmp/password_file.txt &> ../ft/$myString.log
    ./cmd/certutil/${build_dir}/certutil -U &> ../ft/$myString.log
    #gdb --args cmd/fipstest/${build_dir}/fipstest
    grep -n "XPECTED_" ../ft/$myString.log 2> /dev/null
  echo "*****************"
    
done