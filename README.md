# Overview

This repository contains software to be used to connect to the **IBM Cloud Hyper Protect Crypto Services (HPCS)**  offering. For more information regarding this service please review the [HPCS documentation](https://cloud.ibm.com/docs/services/hs-crypto?topic=hs-crypto-get-started).

# Contents

The contents of this repository are offered *as-is* and is subject to change at anytime.

For general information about "Enterprise PKCS #11 over gRPC" (GREP11), please see the official [documentation](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-introduce-cloud-hsm#access-cloud-hsm-pkcs11).

# Code Examples

The examples show how to use the **HPCS offering** to accomplish the following functions:

* Key generation
* Encrypt and decrypt
* Sign and verify
* Wrap and unwrap keys
* Derive keys
* Build message digest
* Retrieve mechanism information

1. Install `node` and `npm` on your machine. The node.js examples were tested with npm version 6.14.11 and node version 14.16.0, running on MacOS.
2. Run `npm install`.
3. Update the following information in the [examples/client.js](examples/client.js#L13-L15) file. Optionally, envrionment variables can be set. The environment variables used are found [here](examples/client.js#L18-L24).

**NOTE:** *This information can be obtained by logging in to your IBM Cloud account and viewing your Hyper Protect Crypto Services (HPCS) instance and IAM information. See the [GREP11 API documentation](https://cloud.ibm.com/docs/services/hs-crypto?topic=hs-crypto-grep11-api-ref) for more information about GREP11*.

```
let apiKey = 'API KEY',
    iamEndpoint = 'https://iam.cloud.ibm.com',
    instanceId = 'INSTANCE ID',
    ep11Address = 'GREP11 URL:PORT';
```
4. Run through each example by executing `node examples/<grep11_example>.js`. For example: `node examples/derive-keys.js`. There are 11 examples in all, each demonstrating various GREP11 operations:

* `mechanism-info.js`: retrieves information about specified GREP11 mechanism
* `mechanism-list.js`: lists all the mechanisms available in GREP11
* `encrypt-and-decrypt.js`: demonstrates and encrypt and decrypt operations
* `digest-single.js`: demonstrates a single-part digest operation
* `digest-multiple.js`: demonstrates a multi-part digest operation
* `sign-and-verify-ecdsa.js`: demonstrates the sign and verify operations using the ECDSA mechanism
* `sign-and-verify-rsa.js`: demonstrates the sign and verify operations using the RSA mechanism
* `sign-and-verify-dsa.js`: demonstrates the sign and verify operations using the DSA mechanism
* `wrap-and-unwrap-key.js`: demonstrates the wrap and unwrap key operations
* `derive-keys.js`: demonstrates the derive key operation
* `derive-keys-dh.js`: derives keys and shares encrypted message between two users using Diffie-Hellman key pairs

5. Alternatively, you can choose to exercise all the operations at once by running the `start_test.sh` script.

The script produces output similar to the following:
```
=== RUN   Example_getMechanismInfo
MECHANISM INFO: { MinKeySize: '16', MaxKeySize: '32', Flags: '32768' }
=== RUN   Example_encryptAndDecrypt
MESSAGE: Hello, this is a very long and creative message without any imagination
CIPHERTEXT: 8dd62265328d24b5811be1b902bd362bd2c5c63209f936fa15821abc1c571cd3ce3aa3d8e7b22551f5c81a333fda8d07911c87ac1350ded4df9a04258ea806c016602fb999d0fe171592163ce66ef1c4
PLAINTEXT: Hello, this is a very long and creative message without any imagination
=== RUN   Example_digest_single
DATA: This is the data longer than 64 bytes This is the data longer than 64 bytes
DIGEST: ad4e0b6e309d192862ec6db692d17072ddd3a98ccd37afe642a04f7ca554c94c
=== RUN   Example_digest_multiple
DATA: This is the data longer than 64 bytes This is the data longer than 64 bytes
DIGEST: ad4e0b6e309d192862ec6db692d17072ddd3a98ccd37afe642a04f7ca554c94c
=== RUN   Example_signAndVerifyUsingRSAKeyPair
DATA: 9fa6c619db022915ff788599c81c27ac5a349834146cfc5034e7353ed5d92727
VERIFIED SIGNATURE: 0200556f59fbcd6dedf66e840815bd082863f1129098f4d645c9e5b3332a31f86c3bd330dbe7679858eaa4fd6fa7a69dfcaf2752386d600ca2e5f522ae19202dca083cdfa7172c5aea37b6f0701e9d62c6e38861e25234cc13b7c5ec587970793696a485f2f84acef992a0c4cf938362b90dded828776978afdf1a0258a48b6afbae999187693275f8a087a0de79600caf1b5ef49b54a1cf4af32295799e5c744b8032b435247f4496b4436063c5f646a053ce772c56b4860c6790b05efa9c073112d30dfdb71763f76ccc7c610aa144970334907068330fbb741d0b2bd85b3ea02850d765c523a9e5a018f80191228c85e32967c759bdde5ac02a7cf6991103
=== RUN   Example_signAndVerifyUsingECDSAKeyPair
DATA: 9fa6c619db022915ff788599c81c27ac5a349834146cfc5034e7353ed5d92727
VERIFIED SIGNATURE: 02cfa0c73082fbdce3a9c2692dd623d6a84dca710cc8f7407ec931baa56d33617d579620cf77d056d384ec3b8dfac632087a30b0f1627d888c6318208c3d8ead
=== RUN   Example_wrapAndUnwrapKey
AES KEY: 00000000000000000000000000000000000000000000000000000000000000005b90a06500b3d6019297804e216dea8d0000000000008d2500000000000000011234b4275791bd98e6f3fb10879436de149c081809aa0e679a42d1c9ea6a22f609b19f4278e7cd9a315945854eb286ab64954126aed72dd61709d6f90201b173bae3776c52aa4f354417ebb79e11473089daa458e4e29c3762dba7737dfe6e62b162df4493dc2f361ee0ff9f0f2c00d4500f3598f243ad46e13f17cc4575154c7ee6b73f2cf73525fc05bd1dc7b5f7b1c62fce8796e5a5678cec3fef4fe999c57efb61721fb3bd6f75954a1216b82b19dd750676524e0480793d226b03c5fadd
WRAPPED: 4ecadf69b151380b3af6acac63dd56dcb15e622997fb040a55de95f3e433cf6d57d97aecbb543377612d5273e209af2d9fb760e33f2222caf18c388b54f0d5ed502b226a789afbf24d20dc7c1a431f408ef9a8473c27407ce3f940bd468240c8bbe2fbade2973f7116815b00ebb2b807a854eb3ef51942896645bf27b7a10cce8a0a41bcccbdc7e556be561451cb4873f436acc0d857564c81badfa7be6b4c72d7d9a52c9ae7972bd787a21601cefd9d714be0fb3ab7e9293b3992b773d6a355634fc982afb6788d8006b2f515a87020ecb65534041dd94e3b6b6149be231196d1f6baefdb1d38754d52dda888a2a364b84708eb5b639109467f694ad72d33a6
CHECKSUM: 8c7c2600000080
UNWRAPPED KEY: 00000000000000000000000000000000000000000000000000000000000000005b90a06500b3d6019297804e216dea8d0000000000000c0100000000000000011234aefcc40ddc5143ab6bfd99409843851c2921e41321e6a90d8cdeaf1d0443b91723e3b42f08aa4aa1c7a9f7aca9372fd63e63c9accc4c4b68ac9efe9b10666174cd9bb74199dc606705d0df83f6b2c536e345ab5f8b7620edaaf8f3db9dd3821f497f6ebe727a1f5d005080e7983999b575304a3d3dad6bbbb67e7371878b5e5176416da3935d2aeefeadf6156c247adecd685d03445c50570235a0674ae156436ec68fed06c4fe93eaf447c127c0b1d74d46193c32561b5d89c88c31ed23ff09a9e364cce480791eb2b1790e27c8
=== RUN   Example_deriveKey
MESSAGE: Hello World!
CIPHERTEXT: c8ffce07e7a2319cb61e5ee09440311c
PLAINTEXT: Hello World!
=== RUN Example_signAndVerifyUsingDSAKeyPair
VERIFIED SIGNATURE 0d916d0ff8c04e496e798d9d262ccf2df5761d0623deb09e1ab8880727862a1440b870061b430012f8ee6a4cb7585ad107ea4a43f146cf10ac5c557d58f8859b
Verified
=== RUN Example_deriveKeysUsingDH
MESSAGE: Hello World!
CIPHERTEXT: e826b709edeac4dbfa23f284ac89af31
PLAINTEXT: Hello World!
```


