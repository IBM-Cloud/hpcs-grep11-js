/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
const async = require('async'),
      client = require('./client'),
      crypto = require('crypto'),
      ep11 = require('../'),
      {pb, util} = ep11;

const dataToSign = crypto.createHash('sha256')
  .update('This data needs to be signed')
  .digest('hex');

const dsaDomainTemplate = new util.AttributeMap(
  new util.Attribute(ep11.CKA_PRIME_BITS, 2048),
);

async.waterfall([
  cb => {
    client.GenerateKey({
      Mech: { Mechanism: ep11.CKM_DSA_PARAMETER_GEN},
      Template: dsaDomainTemplate,
    }, (err, data={}) => {
      cb(err, data.KeyBytes);
    });
  },

  (keyBytes, cb) => {
    const publicKeyTemplate = new util.AttributeMap(
      new util.Attribute(ep11.CKA_VERIFY, true), // to verify a signature
      new util.Attribute(ep11.CKA_EXTRACTABLE, false),
      new util.Attribute(ep11.CKA_IBM_STRUCT_PARAMS, keyBytes),
    );
    const privateKeyTemplate =  new util.AttributeMap(
      new util.Attribute(ep11.CKA_SIGN, true), // to generate a signature
      new util.Attribute(ep11.CKA_PRIVATE, true),
      new util.Attribute(ep11.CKA_SENSITIVE, true),
      new util.Attribute(ep11.CKA_EXTRACTABLE, false),
    );
    client.GenerateKeyPair({
      Mech: {
        Mechanism: ep11.CKM_DSA_KEY_PAIR_GEN
      },
      PubKeyTemplate: publicKeyTemplate,
      PrivKeyTemplate: privateKeyTemplate
    }, (err, keys) => {
      cb(err, keys);
    });
  },

  (keys, cb) => {
    client.SignInit({
      Mech: {
        Mechanism: ep11.CKM_DSA_SHA1
      },
      PrivKey: keys.PrivKeyBytes
    }, (err, data={}) => {
      cb(err, keys, data.State);
    });
  },

  (keys, state, cb) => {
    client.Sign({
      State: state,
      Data: dataToSign
    }, (err, data={}) => {
      cb(err, keys, data.Signature);
    });
  },

  (keys, signature, cb) => {
    client.VerifyInit({
      Mech: {
        Mechanism: ep11.CKM_DSA_SHA1
      },
      PubKey: keys.PubKeyBytes
    }, (err, data={}) => {
      cb(err, signature, data.State);
    });
  },

  (signature, state, cb) => {
    client.Verify({
      State: state,
      Data: dataToSign,
      Signature: signature
    }, (err, data={}) => {
      cb(err, signature);
    });
  }
 ], (err, signature) => {
  if (err) throw err;

  console.log("VERIFIED SIGNATURE", signature.toString('hex'));
  console.log("Verified");
})