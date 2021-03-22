/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const async = require('async'),
      client = require('./client'),
      ep11 = require('../'),
      {util} = ep11;

const message = 'Hello World!';

const dhDomainTemplate = new util.AttributeMap(
  new util.Attribute(ep11.CKA_PRIME_BITS, 2048)
);

client.GenerateKey({
  Mech: { Mechanism: ep11.CKM_DH_PKCS_PARAMETER_GEN},
  Template: dhDomainTemplate,
}, (err, data={}) => { 
  if (err) throw err;

  const commonPublicKeyTemplate = new util.AttributeMap(
    new util.Attribute(ep11.CKA_DERIVE, true),
    new util.Attribute(ep11.CKA_EXTRACTABLE, false),
    new util.Attribute(ep11.CKA_IBM_STRUCT_PARAMS, data.KeyBytes)
  );
  const privateKeyTemplate = new util.AttributeMap(
    new util.Attribute(ep11.CKA_DERIVE, true),
    new util.Attribute(ep11.CKA_PRIVATE, true),
    new util.Attribute(ep11.CKA_SENSITIVE, true),
    new util.Attribute(ep11.CKA_EXTRACTABLE, false)
  );

  const generateKeyPairRequest = {
    Mech: {
      Mechanism: ep11.CKM_DH_PKCS_KEY_PAIR_GEN
    },
    PubKeyTemplate: commonPublicKeyTemplate,
    PrivKeyTemplate: privateKeyTemplate
  };

	// Generate 2 sets of key pairs
  async.timesSeries(2, (i, cb) => {
    client.GenerateKeyPair(generateKeyPairRequest, cb);
  }, (err, results) => {
    if (err) throw err;

    // Grab keys from results; one set for Alice and one set for Bob
    const [alice, bob] = results;

    const deriveKeyTemplate = new util.AttributeMap(
      new util.Attribute(ep11.CKA_CLASS, ep11.CKO_SECRET_KEY),
      new util.Attribute(ep11.CKA_KEY_TYPE, ep11.CKK_AES),
      new util.Attribute(ep11.CKA_VALUE_LEN, 128/8),
			new util.Attribute(ep11.CKA_ENCRYPT, true),
      new util.Attribute(ep11.CKA_DECRYPT, true),
    );

    const derived = [];

    async.eachSeries([
      {PublicKey: alice.PubKeyBytes, PrivateKey: bob.PrivKeyBytes},
      {PublicKey: bob.PubKeyBytes, PrivateKey: alice.PrivKeyBytes}
    ], (data, cb) => {
      const personPublicKey = util.getPubKeyBytesFromDH(data.PublicKey);
			const personPubInteger = util.Asn1DHInteger.decode(personPublicKey);
	
      client.DeriveKey({
        Mech: {
          Mechanism: ep11.CKM_DH_PKCS_DERIVE,
          ParameterB: personPubInteger.toBuffer(),
        },
        Template: deriveKeyTemplate,
        BaseKey: data.PrivateKey
      }, (err, DeriveKeyResponse={}) => {
        if (!err) {
					derived.push(DeriveKeyResponse);
        }
				cb(err);
      });
    }, (err) => {
      if (err) throw err;

      // Grab new keys from results
      const [aliceDerived, bobDerived] = derived;

      // Encrypt and decrypt message with derived keys
      async.waterfall([
        cb => {
					client.GenerateRandom({
            Len: ep11.AES_BLOCK_SIZE
          }, (err, data={}) => {
            cb(err, data.Rnd);
          });
        },

        (iv, cb) => {
          client.EncryptSingle({
            Mech: {
              Mechanism: ep11.CKM_AES_CBC_PAD,
              ParameterB: iv
            },
            Key: aliceDerived.NewKeyBytes,
            Plain: Buffer.from(message)
          }, (err, data={}) => {
            cb(err, iv, data.Ciphered);
          });
        },

        (iv, ciphertext, cb) => {
          client.DecryptSingle({
            Mech: {
              Mechanism: ep11.CKM_AES_CBC_PAD,
              ParameterB: iv
            },
            Key: bobDerived.NewKeyBytes,
            Ciphered: ciphertext
          }, (err, data={}) => {
            cb(err, ciphertext, data.Plain);
          });
        }
      ], (err, ciphertext, plaintext) => {
        if (err) throw err;

        console.log('MESSAGE:', message);
        console.log('CIPHERTEXT:', ciphertext.toString('hex'));
        console.log('PLAINTEXT:', plaintext.toString());

        if (plaintext.toString() !== message) {
          throw new Error('Plaintext does not match original message');
        }
      });
    });
  });
});
