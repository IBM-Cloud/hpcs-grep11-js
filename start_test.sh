#!/bin/bash

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

BASEDIR=$(dirname "$0")

echo "=== RUN   Example_getMechanismInfo"
node $BASEDIR/examples/mechanism-info.js

echo "=== RUN   Example_encryptAndDecrypt"
node $BASEDIR/examples/encrypt-and-decrypt.js

echo "=== RUN   Example_digest_single"
node $BASEDIR/examples/digest-single.js

echo "=== RUN   Example_digest_multiple"
node $BASEDIR/examples/digest-multiple.js

echo "=== RUN   Example_signAndVerifyUsingRSAKeyPair"
node $BASEDIR/examples/sign-and-verify-rsa.js

echo "=== RUN   Example_signAndVerifyUsingECDSAKeyPair"
node $BASEDIR/examples/sign-and-verify-ecdsa.js

echo "=== RUN Example_signAndVerifyUsingDSAKeyPair"
node $BASEDIR/examples/sign-and-verify-dsa.js

# NOTE: Using the Dilithium mechanism is hardware and firmware dependent.  If you receive an error indicating
#       that the CKM_IBM_DILITHIUM mechanism is invalid then the remote HSM currently does not support this mechanism.
# echo "=== RUN Example_signAndVerifyUsingDilithiumKeyPair"
# node $BASEDIR/examples/sign-and-verify-dilithium.js

echo "=== RUN   Example_wrapAndUnwrapKey"
node $BASEDIR/examples/wrap-and-unwrap-key.js

echo "=== RUN   Example_wrapAndUnwrapAttributeBoundKey"
node $BASEDIR/examples/wrap-and-unwrap-attributebound-key.js

echo "=== RUN   Example_deriveKey"
node $BASEDIR/examples/derive-keys.js

echo "=== RUN Example_deriveKeysUsingDH"
node $BASEDIR/examples/derive-keys-dh.js