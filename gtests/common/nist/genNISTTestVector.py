#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import os
import subprocess

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import binascii

script_dir = os.path.dirname(os.path.abspath(__file__))

# Imports a JSON testvector file.
def import_testvector(file):
    """Import a JSON testvector file and return an array of the contained objects."""
    with open(file) as f:
        vectors = json.loads(f.read())
    return vectors

# Convert a test data string to a hex array.
def string_to_hex(string):
    """Convert a string of hex chars to a string representing a C-format array of hex bytes."""
    b = bytearray.fromhex(string)
    result = ', '.join("{:#04x}".format(x) for x in b)
    return result

#now split them into readable lines
def string_line_split(string, group_len, count, spaces):
    result=''
    lstring = string;
    while (len(lstring) > count*group_len):
        result += lstring[:count*group_len].rjust(spaces);
        result += '\n'
        lstring=lstring[count*group_len:];
    result += lstring.rjust(spaces)
    return result

# put it together
def string_to_hex_array(string):
    result="{\n"
    result += string_line_split(' '+string_to_hex(string), 6, 12, 4)
    result += '}'
    return result


mldsa_spki={
    "ML-DSA-44": "30820532300b06096086480165030403110382052100",
    "ML-DSA-65": "308207b2300b0609608648016503040312038207a100",
    "ML-DSA-87": "30820a32300b060960864801650304031303820a2100",
}
mldsa_p11param={
    "ML-DSA-44": "CKP_ML_DSA_44",
    "ML-DSA-65": "CKP_ML_DSA_65",
    "ML-DSA-87": "CKP_ML_DSA_87",
}

class MLDSA_VERIFY():
    key_name=''
    has_name=False
    def init_global(self, group, group_result, out_defs):
        paramSet= group['parameterSet']
        self.paramSet=paramSet
        if not paramSet in mldsa_spki:
            return False
        if 'pk' in group:
            rawkey= group['pk']
            paramSet= group['parameterSet']
            key_name = "kPubKey"+str(group['tgId'])
            key=mldsa_spki[paramSet]+rawkey
            out_defs.append('// Key Type'+paramSet+'\n')
            out_defs.append('static const std::vector<uint8_t> ' + key_name + string_to_hex_array(key) + ';\n\n')
            self.key_name=key_name
            self.has_name=True
            return True
        self.has_name=False
        # only fetch the test types that we support: external
        # pure, and externalMu == false.
        # we can adjust these when we and externalMu support and
        # MLDSA Hash support (if we ever do)
        if 'signatureInterface' in group:
            if group['signatureInterface'] != "external":
                return False
        if 'preHash' in group:
            if group['preHash'] != "pure":
                return False
        if 'externalMu' in group:
            if group['externalMu']:
                return False
        return True
    def format_testcase(self, testcase, testcase_result, out_defs):
        key=mldsa_spki[self.paramSet]+testcase['pk']
        result = '\n// {}\n'.format(self.paramSet)
        result = '// tcID: {}\n'.format(testcase['tcId'])
        result += '{{{},\n'.format(testcase['tcId'])
        result += '// signature\n{},\n'.format(string_to_hex_array(testcase['signature']))
        if self.has_name:
            result += '{},\n'.format(self.key_name)
        else:
            result += '// pubkey\n{},\n'.format(string_to_hex_array(key))
        if 'context' in testcase:
            result += '// context\n{},\n'.format(string_to_hex_array(testcase['context']))
        else:
            result += '// context\n{{}},\n'
        result += '// message\n{},\n'.format(string_to_hex_array(testcase['message']))
        result += '{}}},\n'.format(str(testcase_result['testPassed']).lower())
        display = 'tcID {}: {} '.format(testcase['tcId'],self.paramSet)
        display += 'key({}) message({}) '.format(len(key)/2,len(testcase['message'])/2)
        display += 'signature({}) ctx({}) '.format(len(testcase['signature'])/2,len(testcase['context'])/2,)
        display += '{}'.format(testcase_result['testPassed'])
        print(display)
        return result

class MLDSA_KEYGEN():
    def init_global(self, group, group_result, out_defs):
        paramSet= group['parameterSet']
        self.paramSet = paramSet
        return paramSet in mldsa_p11param
    def format_testcase(self, testcase, testcase_result, out_defs):
        seed=testcase['seed']
        pubk=testcase_result['pk']
        privk=testcase_result['sk']
        result = '\n// {}\n'.format(self.paramSet)
        result = '// tcID: {}\n'.format(testcase['tcId'])
        result += '{{{},\n'.format(testcase['tcId'])
        result += '{},\n'.format(mldsa_p11param[self.paramSet])
        result += '//seed\n{},\n'.format(string_to_hex_array(seed))
        result += '//raw pubkey\n{},\n'.format(string_to_hex_array(pubk))
        result += '//raw privkey\n{}}},\n'.format(string_to_hex_array(privk))
        display = 'tcID {}: {} '.format(testcase['tcId'],self.paramSet)
        display += 'seed({}) pubk({}) '.format(len(seed)/2,len(pubk)/2)
        display += 'privk({})'.format(len(privk)/2)
        print(display)
        return result

def matchID(_id, source, target):
    for i in target:
        if i[_id] == source[_id]:
            return i
    return {}

def generate_vectors_file(params):
    """
    Generate and store a .h-file with test vectors for one test.

    params -- Dictionary with parameters for test vector generation for the desired test.
    """

    cases = import_testvector(os.path.join(script_dir, params['source_dir'] + params['prompt_file']))
    result = import_testvector(os.path.join(script_dir, params['source_dir'] + params['result_file']))

    base_vectors = ""
    if 'base' in params:
        with open(os.path.join(script_dir, params['base'])) as base:
            base_vectors = base.read()
        base_vectors += "\n\n"

    header = standard_params['license']
    header += "\n"
    header += standard_params['top_comment']
    header += "\n"
    header += "#ifndef " + params['section'] + "\n"
    header += "#define " + params['section'] + "\n"
    header += "\n"

    for include in standard_params['includes']:
        header += "#include " + include + "\n"

    header += "\n"

    if 'includes' in params:
        for include in params['includes']:
            header += "#include " + include + "\n"
        header += "\n"

    shared_defs = []
    vectors_file = base_vectors + params['array_init']

    for group in cases['testGroups']:
        group_result = matchID('tgId', group, result['testGroups']);
        if (not params['formatter'].init_global(group, group_result, shared_defs)):
            continue;
        for test in group['tests']:
            test_result = matchID('tcId', test, group_result['tests']);
            vectors_file += params['formatter'].format_testcase(test, test_result, shared_defs)

    vectors_file = vectors_file[:params['crop_size_end']] + '\n};\n\n'
    vectors_file += "#endif // " + params['section'] + '\n'

    with open(os.path.join(script_dir, params['target']), 'w') as target:
        target.write(header)
        for definition in shared_defs:
            target.write(definition)
        target.write(vectors_file)


standard_params = {
    'includes': ['"testvectors_base/test-structs.h"'],
    'license':
"""/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */
 """,

    'top_comment':
"""/* This file is generated from sources in nss/gtests/common/wycheproof
 * automatically and should not be touched manually.
 * Generation is trigged by calling python3 genTestVectors.py */
 """
}

# Parameters that describe the generation of a testvector file for each supoorted test.
# source -- relative path to the wycheproof JSON source file with testvectors.
# base -- relative path to non-wycheproof vectors.
# target -- relative path to where the finished .h-file is written.
# array_init -- string to initialize the c-header style array of testvectors.
# formatter -- the test case formatter class to be used for this test.
# crop_size_end -- number of characters removed from the end of the last generated test vector to close the array definition.
# section -- name of the section
# comment -- additional comments to add to the file just before definition of the test vector array.

ml_dsa_verify_params = {
    'source_dir': 'source_vectors/',
    'test_name': 'ML-DSA-sigVer-FIPS204',
    'tag': 'v1.1.0.40',
    'prompt_file': 'ml_dsa_verify_prompt.json',
    'result_file': 'ml_dsa_verify_result.json',
    'target': '../testvectors/ml-dsa-verify-vectors.h',
    'array_init': 'const MlDsaVerifyTestVector kMLDsaNISTVerifyVectors[] = {\n',
    'formatter' : MLDSA_VERIFY(),
    'crop_size_end': -2,
    'section': 'mldsa_verify_vectors_h__',
    'comment' : ''
}

ml_dsa_keygen_params = {
    'source_dir': 'source_vectors/',
    'test_name': 'ML-DSA-keyGen-FIPS204',
    'tag': 'v1.1.0.40',
    'prompt_file': 'ml_dsa_keygen_prompt.json',
    'result_file': 'ml_dsa_keygen_result.json',
    'target': '../testvectors/ml-dsa-keygen-vectors.h',
    'array_init': 'const MlDsaKeyGenTestVector kMLDsaNISTKeyGenVectors[] = {\n',
    'formatter' : MLDSA_KEYGEN(),
    'crop_size_end': -2,
    'section': 'mldsa_keygen_vectors_h__',
    'comment' : ''
}


def update_tests(tests):

    remote_base = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/refs/tags/"
    for test in tests:
        remote = remote_base+test['tag']+"/gen-val/json-files/"+test['test_name']+"/"
        subprocess.check_call(['wget', remote+"/prompt.json", '-O',
                               script_dir+'/'+test['source_dir']+test['prompt_file']])
        subprocess.check_call(['wget', remote+"/expectedResults.json", '-O',
                               script_dir+'/'+test['source_dir']+test['result_file']])

def generate_test_vectors():
    """Generate C-header files for all supported tests."""
    all_tests = [ ml_dsa_verify_params, ml_dsa_keygen_params ]
    update_tests(all_tests)
    for test in all_tests:
        generate_vectors_file(test)

def main():
    generate_test_vectors()

if __name__ == '__main__':
    main()
