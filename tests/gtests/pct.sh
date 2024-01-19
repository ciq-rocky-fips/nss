#! /bin/bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

########################################################################
#
# similar to all.sh this file runs drives gtests.
#
# needs to work on all Unix and Windows platforms
#
# special strings
# ---------------
#   FIXME ... known problems, search for this string
#   NOTE .... unexpected behavior
#
########################################################################

############################## gtest_init ##############################
# local shell function to initialize this script
########################################################################
gtest_init()
{
  cd "$(dirname "$1")"
  pwd
  SOURCE_DIR="$PWD"/../..

  if [ -z "${INIT_SOURCED}" -o "${INIT_SOURCED}" != "TRUE" ]; then
      cd ../common
      . ./init.sh
  fi

  SCRIPTNAME=gtests.sh
  . "${QADIR}"/common/certsetup.sh

  if [ -z "${CLEANUP}" ] ; then   # if nobody else is responsible for
    CLEANUP="${SCRIPTNAME}"       # cleaning this script will do it
  fi

  mkdir -p "${GTESTDIR}"
  cd "${GTESTDIR}"
}

########################## gtest_start #############################
# Local function to actually start the test
####################################################################
gtest_start()
{
  echo "PCTs: ${GTESTS}"
  for i in ${GTESTS}; do
    echo "${BINDIR}/$i"
    if [ ! -f "${BINDIR}/$i" ]; then
      html_unknown "Skipping $i (not built)"
      continue
    fi
    DIR="${GTESTDIR}/$i"
    html_head "$i"
    if [ ! -d "$DIR" ]; then
      mkdir -p "$DIR"
      echo "${BINDIR}/certutil" -N -d "$DIR" --empty-password 2>&1
      "${BINDIR}/certutil" -N -d "$DIR" --empty-password 2>&1

      PROFILEDIR="$DIR" make_cert dummy p256 sign
    fi
    pushd "$DIR"
    GTESTREPORT="$DIR/report.xml"
    PARSED_REPORT="$DIR/report.parsed"
    # The mozilla::pkix gtests cause an ODR violation that we ignore.
    # See bug 1588567.
    if [ "$i" = "mozpkix_gtest" ]; then
      EXTRA_ASAN_OPTIONS="detect_odr_violation=0"
    fi
    # NSS CI sets a lower max for PBE iterations, otherwise cert.sh
    # is very slow. Unset this maxiumum for softoken_gtest, as it
    # needs to check the default value.
    if [ "$i" = "softoken_gtest" ]; then
      OLD_MAX_PBE_ITERATIONS=$NSS_MAX_MP_PBE_ITERATION_COUNT
      unset NSS_MAX_MP_PBE_ITERATION_COUNT
    fi
    echo "executing $i"
    #########################
    # Reset the log - another process was generating errors PCT errors
    mv /tmp/test.log ./Startup.log
    #########################

    #ASAN_OPTIONS="$ASAN_OPTIONS:$EXTRA_ASAN_OPTIONS" "${BINDIR}/$i" \
    #ASAN_OPTIONS="$ASAN_OPTIONS:$EXTRA_ASAN_OPTIONS" gdb --args "${BINDIR}/$i" \
    ASAN_OPTIONS="$ASAN_OPTIONS:$EXTRA_ASAN_OPTIONS" "${BINDIR}/$i" \
                 -s "${SOURCE_DIR}/gtests/$i" \
                 -d "$DIR" -w --gtest_output=xml:"${GTESTREPORT}" \
                              --gtest_filter="${GTESTFILTER:-*}"
    
    html_msg $? 0 "$i run successfully"
    if [ "$i" = "softoken_gtest" ]; then
      export NSS_MAX_MP_PBE_ITERATION_COUNT=$OLD_MAX_PBE_ITERATIONS
    fi

    echo "test output dir: ${GTESTREPORT}"
    echo "processing the parsed report"
    gtest_parse_report ${GTESTREPORT}
    popd
  done
}

gtest_cleanup()
{
  html "</TABLE><BR>"
  . "${QADIR}"/common/cleanup.sh
}

################## main #################################################
PWD=$(pwd)
export NSS_FIPS_LOGGING="FILE"
export NSS_FIPS_FUNC_TEST="FT"

export LD_PRELOAD="$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib/libsmime3.so \
$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib/libnsssysinit.so \
$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib/libnssutil3.so \
$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib/libnssdbm3.so \
$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib/libsoftokn3.so \
$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib/libfreeblpriv3.so \
$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib/libfreebl3.so \
$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib/libnssckbi-testlib.so \
$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib/libnssckbi.so \
$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib/libssl3.so \
$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib/libpkcs11testmodule.so"

export PATH=.:$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/bin:$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_OBJ.OBJ/lib:/bin:/usr/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin
export LD_LIBRARY_PATH=$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib:

export CPU_ARCH="x86_64"
export NSS_DISABLE_AVX2=0
export OBJDIR=Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ
export BINDIR=$PWD/../dist/Linux4.18_x86_64_cc_glibc_PTH_64_DBG.OBJ/bin
#logger "START of NSS FIPS testing"
gtest_init "$0"
echo "*****************************" > summary.log
echo "PCT SUCCESS RUN" >> summary.log
GTESTS="${GTESTS:-fips_gtest}"
gtest_start

mv /tmp/test.log ./SUCCESS.log
echo "*****************************" >> summary.log
grep "pair-wise\|PCT\|FAILED" ./SUCCESS.log >> summary.log
echo "*****************************" >> summary.log

#myString="${val:1}"
#export NSS_FIPS_FUNC_TEST_NAMES=$myString
#echo "*****************************"
#echo "inducing failure: $myString"
#echo "*****************************"
#gtest_start


echo "*****************************" >> summary.log
echo "inducing failure: :RSA_PCT.ENCRYPT" >> summary.log
export NSS_FIPS_FUNC_TEST_NAMES="RSA_PCT.ENCRYPT" 
GTESTS="${GTESTS:-rsa_gtest}"
gtest_start
mv /tmp/test.log ./RSA_PCT.ENCRYPT.log
echo "*****************************">> summary.log
grep "EXPECTED" ./RSA_PCT.ENCRYPT.log >> summary.log
echo "*****************************">> summary.log


echo "*****************************" >> summary.log
echo "inducing failure: :RSA_PCT.DECRYPT" >> summary.log
export NSS_FIPS_FUNC_TEST_NAMES=":RSA_PCT.DECRYPT" 
GTESTS="${GTESTS:-rsa_gtest}"
gtest_start
mv /tmp/test.log ./RSA_PCT.DECRYPT.log
echo "*****************************" >> summary.log
grep "EXPECTED" ./RSA_PCT.DECRYPT.log >> summary.log
echo "*****************************" >> summary.log

echo "*****************************" >> summary.log
echo "inducing failure: :RSA_PCT.SIGN" >> summary.log
export NSS_FIPS_FUNC_TEST_NAMES=":RSA_PCT.SIGN"
GTESTS="${GTESTS:-rsa_gtest}"
gtest_start
mv /tmp/test.log ./RSA_PCT.SIGN.log
echo "*****************************" >> summary.log
grep "EXPECTED" ./RSA_PCT.SIGN.log >> summary.log
echo "*****************************" >> summary.log

echo "*****************************" >> summary.log
echo "inducing failure: :RSA_PCT.VERIFY" >> summary.log
export NSS_FIPS_FUNC_TEST_NAMES=":RSA_PCT.VERIFY"
GTESTS="${GTESTS:-rsa_gtest}"
gtest_start
mv /tmp/test.log ./RSA_PCT.VERIFY.log
echo "*****************************" >> summary.log
grep "EXPECTED" ./RSA_PCT.VERIFY.log >> summary.log
echo "*****************************" >> summary.log

echo "*****************************" >> summary.log
echo "inducing failure: :ECDSA_PCT.SIGN" >> summary.log
export NSS_FIPS_FUNC_TEST_NAMES=":ECDSA_PCT.SIGN" 
GTESTS="${GTESTS:-ec_gtest}"
gtest_start
mv /tmp/test.log ./ECDSA_PCT.SIGN.log
echo "*****************************" >> summary.log
grep "EXPECTED" ./ECDSA_PCT.SIGN.log >> summary.log
echo "*****************************" >> summary.log

echo "*****************************" >> summary.log
echo "inducing failure: :ECDSA_PCT.VERIFY" >> summary.log
export NSS_FIPS_FUNC_TEST_NAMES=":ECDSA_PCT.VERIFY" 
GTESTS="${GTESTS:-ec_gtest}"
gtest_start
mv /tmp/test.log ./ECDSA_PCT.VERIFY.log
echo "*****************************" >> summary.log
grep "EXPECTED" ./ECDSA_PCT.VERIFY.log >> summary.log
echo "*****************************" >> summary.log

echo "*****************************" >> summary.log
echo "inducing failure: :ECDH_DERIVE.DERIVE" >> summary.log
export NSS_FIPS_FUNC_TEST_NAMES=":ECDH_DERIVE.DERIVE"
GTESTS="${GTESTS:-ec_gtest}"
gtest_start
mv /tmp/test.log ./ECDH_PCT.DERIVE.log
echo "*****************************" >> summary.log
grep "EXPECTED" ./ECDH_PCT.DERIVE.log >> summary.log
echo "*****************************" >> summary.log

echo "*****************************" >> summary.log
echo "inducing failure: :DSA_PCT.SIGN" >> summary.log
export NSS_FIPS_FUNC_TEST_NAMES=":DSA_PCT.SIGN"
GTESTS="${GTESTS:-dsa_gtest}"
gtest_start
mv /tmp/test.log ./DSA_PCT.SIGN.log
echo "*****************************" >> summary.log
grep "EXPECTED" ./DSA_PCT.SIGN.log >> summary.log
echo "*****************************" >> summary.log

echo "*****************************" >> summary.log
echo "inducing failure: :DSA_PCT.VERIFY" >> summary.log
export NSS_FIPS_FUNC_TEST_NAMES=":DSA_PCT.VERIFY"
GTESTS="${GTESTS:-dsa_gtest}"
gtest_start
mv /tmp/test.log ./DSA_PCT.VERIFY.log
echo "*****************************" >> summary.log
grep "EXPECTED" ./DSA_PCT.VERIFY.log >> summary.log
echo "*****************************" >> summary.log

echo "*****************************" >> summary.log
echo "inducing failure: :DH_PKCS_DERIVE.DERIVE" >> summary.log
export NSS_FIPS_FUNC_TEST_NAMES=":DH_PKCS_DERIVE.DERIVE"
GTESTS="${GTESTS:-dh_gtest}"
gtest_start
mv /tmp/test.log ./DH_PKCS_DERIVE.DERIVE.log
echo "*****************************" >> summary.log
grep "EXPECTED" ./DH_PKCS_DERIVE.DERIVE.log >> summary.log
echo "*****************************" >> summary.log

cat ./summary.log
gtest_cleanup


#May 19 10:13:31 localhost fips_gtest[1303645]: NSS:SUCCESS pkcs11c.c:5861 NSC_GenerateKeyPair::ECDSA: self-test: pair-wise consistency test
#May 19 10:13:31 localhost fips_gtest[1303645]: NSS:SUCCESS pkcs11c.c:5870 NSC_GenerateKeyPair::ECDH: self-test: pair-wise consistency test
#May 19 10:13:31 localhost fips_gtest[1303645]: NSS:SUCCESS pkcs11c.c:5870 NSC_GenerateKeyPair::RSA: self-test: pair-wise consistency test
#May 19 10:13:31 localhost fips_gtest[1303645]: NSS:SUCCESS pkcs11c.c:5870 NSC_GenerateKeyPair::DSA: self-test: pair-wise consistency test
#May 19 10:13:31 localhost fips_gtest[1303645]: NSS:SUCCESS pkcs11c.c:5870 NSC_GenerateKeyPair::DH: self-test: pair-wise consistency test

