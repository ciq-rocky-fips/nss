
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
Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/pk11mode -v

#ldd Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/pk11mode
