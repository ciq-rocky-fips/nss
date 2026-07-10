#!/bin/sh
declare -a versions
declare -a modes
declare -a type
versions=(ml_dsa_44 ml_dsa_65 ml_dsa_87)
modes=(2 3 5)
types=(44 65 87)
keep=0
clean=0
update=0
clean_gen=0
branch="master"

library=leancrypto
git_url=https://github.com/smuellerDD/leancrypto
ml_dsa_src=ml-dsa/src
#cpufeatures.h
#test_helper.h

header_gen_list=( lc_dilithium_44.h lc_dilithium_65.h lc_dilithium_87.h)
header_gen_internal_list=( lc_memory_support.h )
header_internal_list=( alignment.h atomic_bool.h atomic.h binhexbin.h
    bitshift_be.h bitshift.h bitshift_le.h bool.h build_bug_on.h
    compare.h conv_be_le.h errno_private-base.h errno_private.h
    ext_headers.h fips_mode.h helper.h initialization.h lc_init.h
    lc_memcmp_secure.h lc_memcpy_secure.h lc_memory_support.h.in
    lc_memset_secure.h lc_status.h left_encode.h math_helper.h
    mutex_w.h null_buffer.h ret_checkers.h rotate.h
    sidechannel_resistantce.h signature_domain_separation.h
    small_stack_support.h timecop.h visibility.h xor256.h xor.h )
header_api_list=(dilithium_type.h lc_dilithium.h)
header_list=( dilithium_debug.h dilithium_ntt.h dilithium_pack.h dilithium_pct.h
        dilithium_poly.h dilithium_poly_c.h dilithium_poly_common.h
        dilithium_polyvec.h dilithium_polyvec_c.h dilithium_reduce.h
        dilithium_rounding.h dilithium_service_helpers.h
        dilithium_signature_c.h dilithium_signature_impl.h dilithium_zetas.h)
internal_list=(signature_domain_separation.c)
common_list=(dilithium_api.c dilithium_zetas.c)
specific_list=( dilithium_ntt.c dilithium_poly.c dilithium_rounding.c
        dilithium_signature_c.c dilithium_signature_helper.c)


process_versions()
{
    echo "process_version($3)" >&2
    local -n vers=$1
    local -n mods=$2
    declare -p vers
    declare -p mods 
    vers=()
    mods=()
    for i in ${3//;/ }
    do
        ver=${i%%:*}
        mod=${i##*:}
        echo "spec=/$i/ ver=/$ver/ mod=/$mod/" >&2
        if [[ "$ver" = "" || "$mod" = "" ]]; then
            echo "invalid version spec \"$i\"" >&2
            return 1
        fi
        vers+=($ver)
        mods+=($mod)
    done
    return 0
}

usage()
{
    echo "usage: ${0##*/} [--keep_intermediate] [--clean_library]" >&2
    echo "          [--version list_of_versions_and_modes]" >&2
    echo "          [--update] [--branch]" >&2
    echo "--keep_intermediate  don't delete intermediate files used to generate headers" >&2
    echo "--clean_library      remove old library directory before starting" >&2
    echo "--clean_generated    remove generated files before starting" >&2
    echo "--versions           ';' separated list of versions and modes. of the form:" >&2
    echo "                     version:mode. example:" >&2
    echo "                     \"ml_dsa_44_ref:2;ml_dsa_65_avx:3;ml_dsa_65_ref:3\"" >&2
    echo "--update             if liboq directory exists, update it" >&2
    echo "--branch             select the git branch to use" >&2
    exit 1
}


while true ; do
    case "$1" in
        --keep_intermediate|-k) keep=1; shift
            ;;
        --clean_leancrypto|-C)
            clean=1; shift
            ;;
        --clean_generated|-c)
            clean_gen=1; shift
            ;;
        -versions|-v)
            process_versions versions modes "$2"
            if (( $? != 0 || ${#modes[@]} != ${#versions[@]} )); then
                echo "not all versions have a mode \"$2\"" >&2
                echo "number modes=${#modes}, number versions=${#versions}" >&2
                echo "versions:${versions[*]}" >&2
                echo "modes:${modes[*]}" >&2
                usage
            fi
            shift 2
            ;;
        --update|-u)
            update=1; shift
            ;;
        --branch|-b)
            branch="$2"; shift 2
            ;;
        "")
            break
            ;;
        *)
            echo "$0: Unknown option: \"$1\"" >&2
            usage
    esac
done


# first fetch and builds leancrypto
top=$(pwd)
echo "--------------- fetching $library"
if  [ -d $library ]; then
    if (( $clean == 1 )); then
        rm -rf $library
        git clone -b main $giturl
    elif (( $update == 1 )); then
        (cd $library ; git checkout main ; git pull)
    fi
else
    git clone -b main $giturl
fi
cd $library
git checkout $branch
if [ $? != 0 ]; then
    echo "branch \"$branch\" not found" >&2
    echo "valid branches and tags are: " >&2
    git branch -l >&2
    git tag -l >&2
    exit 1
fi
libdir=$(pwd)
ml_dsa_dir=${libdir}/${ml_dsa_src}
if [ ! -d $ml_dsa_dir ]; then
    echo "ml_dsa not avaliable on this branch or tag ${branch}" >&2
    exit 1
fi

# now set up everything
if (( clean_gen == 1 )); then
    (cd $top ; rm -f ml_dsa_* fips202.h randombytes.h $library_git_version.txt )
fi
rm -rf build
mkdir build
meson setup build -Ddilithium_ed25519=disabled -Ddilithium_ed448=disabled
cd build
mkdir sed_scripts
mkdir generated_code
build=$(pwd)
sed_scripts=${build}/sed_scripts
generated_code=${build}/generated_code
cd ${libdir}

# these are used to allow is to create 'max' defines
# we find the value from each of the different lengths and then we
# keep the maximum, so we can define our max value in terms of that value
pub_size=0
pub_define="UNKNOWN"
priv_size=0
priv_define="UNKNOWN"
sig_size=0
sig_define="UNKNOWN"
seed_size=0
seed_define="UNKNOWN"

# ml_dsa_api.h is a completely generated header. It basically resolves the defines in the various
# xxxx_sign.h headers, which uses macros redefine all the functions, but they use the same macro and
# function names, so the we can't have a single file that includes all the definitions. library itself
# handles this by creating their own c stubs for each of the functions. We've already name deconflicted
# the filenames, so since we have this program we can safely create a proper header file.
#cat > ${generated_code}/ml_dsa_api.h << __EoF__
#ifndef ML_DSA_API_H
#define ML_DSA_API_H
#// This is a generated file from the various XXX_sign.h files
#include <stddef.h>
#include "ml_dsa_apit.h"
#__EoF__
cat > ${generated_code}/ml_dsa_apit.h << __EoF__
// This is a generated file from the various XXX_sign.h files
#ifndef ML_DSA_APIT_H
#define ML_DSA_APIT_H

// to make the function defines work
#ifndef RNDBYTES
#define RNDBYTES 32
#endif
__EoF__

for i in ${commonlist[@]}
do
     cp ${ml_dsa_dir}/$i ${generated_code}/
done
for file in ${header_internal_list[@]}
do
    cp ${libdir}/internal/api/${file} ${generated_code}/${file}
done
for file in ${header_gen_internal_list=[@]}
do
    cp ${libdir}/build/internal/api/${file} ${generated_code}/${file}
done
for file in ${header_gen_list[@]}
do
    cp ${libdir}/build/ml-dsa/api/${file} ${generated_code}/${file}
done
for file in ${header_api_list[@]}
do
    cp ${ml_dsa_dir}/../api/${file} ${generated_code}/${file}
done
for file in ${header_list[@]}
do
    cp ${ml_dsa_dir}/${file} ${generated_code}/${file}
done
for file in ${internal_list[@]}
do
    cp ${libdir}/internal/src/${file} ${generated_code}/${file}
done
for file in ${common_list[@]}
do
    target_file=${file#dilithium}
    cp ${ml_dsa_dir}/${file} ${generated_code}/mldsa${target_file}
done
# now process the each of the versions we are woring on.
for i in ${!versions[@]}
do
    sig=${versions[$i]}
    mode=${modes[$i]}
    #ls *.h | sed "s/\(.*\)/s;\1;${sig}_\1;/" > ${sed_scripts}/header_rename_${sig}.sed
    #echo "s;<oqs/oqs.h>;\"blapi.h\";" >> ${sed_scripts}/header_rename_${sig}.sed
    #echo "s;OQS_API;;g" >> ${sed_scripts}/header_rename_${sig}.sed
    echo "#define LC_DILITHIUM_TYPE_${types[$i]} 1" > ${generated_code}/${sig}_def_header.h

    echo "------------------------- Processing $sig mode=$mode ... "
    for file in ${specific_list[@]}
    do
        target_file=${file#dilithium}
        echo -n -e "fixup ${file} to ${sig}_${file}\r"
        tmp=${generated_code}/${sig}${file}_tmp
        cat ${generated_code}/${sig}_def_header.h ${ml_dsa_dir}/${file} > ${tmp}
        #sed -f ${sed_scripts}/header_rename_${sig}.sed ${file} > ${tmp}
        #unifdef -DLC_DILITHIUM_MODE=${mode} ${tmp} > ${generated_code}/${sig}_${file}
        cp ${tmp} ${generated_code}/${sig}${target_file}
        rm ${tmp}
    done
    echo ""
    cd ${generated_code}
 #process ${sig}_sign.h to get all the function defines into our ml_dsa_api.h
#    echo "" >> ${generated_code}/ml_dsa_api.h
#    echo "// from ${sig}_sign.h " >> ${generated_code}/ml_dsa_api.h
#grep -v '^#' ${sig}_sign.h | grep -v "^$" | sed -e "s/crypto_sign/pqcrystals_${sig}/" >> ${generated_code}/ml_dsa_api.h

 # now let's get unrolled defines for the various sizes (keys, signatures, seeds). We use a C program
 # and make C evaluate the final value of several defines which are calculated on the fly.
#   echo "#include \"${sig}_params.h\"" > ./${sig}_extract_defines.c
#    echo "const char *sign_ver=\"${sig^^}\";" >> ./${sig}_extract_defines.c
#    echo "const char *l_sign_ver=\"${sig}\";" >> ./${sig}_extract_defines.c
#    cat >> ./${sig}_extract_defines.c << __EoF__
##include <stdio.h>
#int main(int argc, char **arv) {
#    printf("\n");
#    printf("//  from %s_sign.h\n", l_sign_ver);
#    printf("#define %s_PUBLICKEY_BYTES %d\n", sign_ver, CRYPTO_PUBLICKEYBYTES);
#    printf("#define %s_PRIVATEKEY_BYTES %d\n", sign_ver, CRYPTO_SECRETKEYBYTES);
#    printf("#define %s_SIGNATURE_BYTES %d\n", sign_ver, CRYPTO_BYTES);
#    printf("#define %s_SEED_BYTES %d\n", sign_ver, SEEDBYTES);
#}
#__EoF__
#    cc -o ${sig}_extract_defines ${sig}_extract_defines.c
#    ./${sig}_extract_defines >> ${generated_code}/ml_dsa_apit.h
#    new_size=$(./${sig}_extract_defines | grep PUBLICKEY | awk '{ print $NF }')
#    if (( new_size > pub_size )); then
#        pub_size=$new_size
#        pub_define=${sig^^}
#    fi
#    new_size=$(./${sig}_extract_defines | grep PRIVATEKEY | awk '{ print $NF }')
#    if (( new_size > priv_size )); then
#        priv_size=$new_size
#        priv_define=${sig^^}
#    fi
#    new_size=$(./${sig}_extract_defines | grep SIGNATURE | awk '{ print $NF }')
#    if (( new_size > sig_size )); then
#        sig_size=$new_size
#        sig_define=${sig^^}
#    fi
#    new_size=$(./${sig}_extract_defines | grep SEED | awk '{ print $NF }')
#    if (( new_size > seed_size )); then
#        seed_size=$new_size
#        seed_define=${sig^^}
#    fi
#    if (( $keep != 1 )); then
#        rm  ${sig}_extract_defines*
#    fi
    # sigh clang20 knows about type c, but we only have cpp in our
    # .clang-format file, tell clang to use .cpp
    for file in *.[c]
    do
        base=$(basename $file .c)
        echo clang-format --assume-filename=${base}.cpp --sort-includes=false -i ${file}
        cat ${file} | clang-format --assume-filename=${base}.cpp --sort-includes=false  >${file}.clang
        mv ${file}.clang ${file}
    done
    for file in *.[h]
    do
        clang-format --sort-includes=false -i ${file}
    done
    tar cf  - . | (cd ${top} ; tar xf -)
    cd ${libarary}
done

#if (( $version_found == 0 ));  then
#    echo "no requested versions (${versions[*]}) found in this branch ($branch)" >&2
#    echo "valid versions are:" >&2
#    ls ${ml_dsa_dir} | grep pqcrystals | sed  's;pqcrystals-dilithium-standard[_|-];;' >&2
#    exit 1
#fi

echo "" >> ${generated_code}/ml_dsa_apit.h
#echo "// create the max defines" >> ${generated_code}/ml_dsa_apit.h
#echo "#define MAX_MLDSA_REF_PRIVATE_KEY_LEN ${priv_define}_PRIVATEKEY_BYTES" >> ${generated_code}/ml_dsa_apit.h
#echo "#define MAX_MLDSA_REF_PUBLIC_KEY_LEN ${priv_define}_PUBLICKEY_BYTES" >> ${generated_code}/ml_dsa_apit.h
#echo "#define MAX_MLDSA_REF_SIGNATURE_LEN ${priv_define}_SIGNATURE_BYTES" >> ${generated_code}/ml_dsa_apit.h
#echo "#define MAX_MLDSA_REF_SEED_LEN ${priv_define}_SEED_BYTES" >> ${generated_code}/ml_dsa_apit.h
#echo "#endif /* ML_DSA_API_H */" >> ${generated_code}/ml_dsa_api.h
echo "#endif /* ML_DSA_APIT_H */" >> ${generated_code}/ml_dsa_apit.h

cp ${generated_code}/ml_dsa_api.h ${top}
cp ${generated_code}/ml_dsa_apit.h ${top}
cd ${top}
echo "------------------------- wrote ml_dsa_apit.h : ... "
# remember what version we are using
(cd ${library}; git branch -v) > leancrypto_git_version.txt
# Now write out  the fixed files
cat > fips202.h << __EoF__
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
#define shake128_inc_init(ptr) \
    (*(ptr))=SHAKE_128_NewContext(); \
    SHAKE_128_Begin(*(ptr))
#define shake128_inc_absorb(ptr, input, inlen) \
    SHAKE_128_Absorb(*(ptr), input, inlen)
#define shake128_inc_finalize(ptr)
#define shake128_inc_squeeze(output, outlen, ptr)  \
    SHAKE_128_SqueezeEnd(*(ptr), output, outlen)
#define shake128_inc_ctx_release(ptr)  \
    SHAKE_128_DestroyContext(*(ptr), PR_TRUE)
#define shake128_inc_ctx_reset(ptr)  \
    SHAKE_128_Begin(ptr)
#ifdef NOT_SUPPORTED
#define shake128_inc_ctx_clone OQS_SHA3_shake128_inc_ctx_clone
#endif

typedef SHAKE_256Context *shake256incctx;
#define shake256_inc_init(ptr) \
    (*(ptr))=SHAKE_256_NewContext(); \
    SHAKE_256_Begin(*(ptr))
#define shake256_inc_absorb(ptr, input, inlen) \
    SHAKE_256_Absorb(*(ptr), input, inlen)
#define shake256_inc_finalize(ptr)
#define shake256_inc_squeeze(output, outlen, ptr) \
    SHAKE_256_SqueezeEnd(*(ptr), output, outlen)
#define shake256_inc_ctx_release(ptr)  \
    SHAKE_256_DestroyContext(*(ptr), PR_TRUE)
#define shake256_inc_ctx_reset(ptr) \
    SHAKE_256_Begin(*ptr)

#ifdef NOT_SUPPORTED
#define shake128_absorb_once OQS_SHA3_shake128_absorb_once
void OQS_SHA3_shake128_absorb_once(shake128incctx *state, const uint8_t *in, size_t inlen);

#define shake256_absorb_once OQS_SHA3_shake256_absorb_once
void OQS_SHA3_shake256_absorb_once(shake256incctx *state, const uint8_t *in, size_t inlen);
#endif

#define shake128_squeezeblocks(OUT, NBLOCKS, STATE)         shake128_inc_squeeze(OUT, (NBLOCKS)*SHAKE128_RATE, STATE)

#define shake256_squeezeblocks(OUT, NBLOCKS, STATE)         shake256_inc_squeeze(OUT, (NBLOCKS)*SHAKE256_RATE, STATE)

#endif
__EoF__
cat > randombytes.h << __EoF__
// SPDX-License-Identifier: MIT
// NSS stub for liboqs randombytes.h

#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

// run the random number generator through our mldsa code so we can support
// CKA_SEED (both acquiring it and generating keys from it) and
// DETERMINISTIC signatures (by returning zeros from the RNG)
void mldsa_GetRandomBytes(unsigned char *rdn, int bytes);
#define randombytes mldsa_GetRandomBytes

#endif
__EoF__
clang-format -sort-includes=false -i randombytes.h fips202.h ml_dsa_apit.h ml_dsa_api.h
#output our generated files for review
echo "ml_dsa_abit.h -----------------"
cat ml_dsa_apit.h
echo "git version used -----------------"
cat oqs_git_version.txt
#rm -rf ${liboqs}
exit 0
