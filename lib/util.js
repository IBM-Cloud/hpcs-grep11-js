/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const asn1 = require('asn1.js'),
      Long = require('long'),
      {ConstantType} = require('./header_consts'),
      util = require('util');

const Asn1OID = exports.Asn1OID = asn1.define('Asn1OID', function () { this.objid(); });

const Asn1ECAlgorithmIdentifier = asn1.define('Asn1ECAlgorithmIdentifier', function () {
  this.seq().obj(
    this.key('algorithm').objid(),
    this.key('curve').objid()
  );
});

const Asn1ECPublicKey = exports.Asn1ECPublicKey = asn1.define('Asn1ECPublicKey', function () {
  this.seq().obj(
    this.key('algorithm').use(Asn1ECAlgorithmIdentifier),
    this.key('point').bitstr()
  );
});

const DH2Int = asn1.define('DH2Int', function () {
  this.seq().obj(
    this.key('Prime').int(),
    this.key('Base').int()
  )
})
const Asn1DHAlgorithmIdentifier = asn1.define('Asn1DHAlgorithmIdentifier', function () {
  this.seq().obj(
    this.key('algorithm').objid(),
    this.key('PB').use(DH2Int)
  );
});

const Asn1DHPublicKey = exports.Asn1DHPublicKey = asn1.define('Asn1DHPublicKey', function () {
  this.seq().obj(
    this.key('Parameter').use(Asn1DHAlgorithmIdentifier),
    this.key('PublicKey').bitstr()
  );
})

const Asn1DHInteger = exports.Asn1DHInteger = asn1.define('Asn1DHInteger', function () {
  this.key("PublicKeyInteger").int()
});

// ASN1-encoded objects
exports.OIDNamedCurveP224 = Asn1OID.encode([1, 3, 132, 0, 33]);
exports.OIDNamedCurveP256 = Asn1OID.encode([1, 2, 840, 10045, 3, 1, 7]);
exports.OIDNamedCurveP384 = Asn1OID.encode([1, 3, 132, 0, 34]);
exports.OIDNamedCurveP521 = Asn1OID.encode([1, 3, 132, 0, 35]);
exports.OIDECPublicKey = Asn1OID.encode([1, 2, 840, 10045, 2, 1]);


class AttributeMap {
  constructor(...attributes) {
    attributes.forEach(attr => {
      if (!(attr instanceof Attribute)) {
        throw new Error('Attribute must be an Attribute');
      }

      this[attr.key] = attr.value;
    });
  }
}

exports.AttributeMap = AttributeMap;


class Attribute {
  constructor(key, value) {
    if (!(key instanceof ConstantType)) {
      throw new Error('Attribute key must be instance of ConstantType');
    }

    this.key = key;
    this.value = convertValue(value);
  }
}

exports.Attribute = Attribute;


function convertValue(value) {
  if (Long.isLong(value)) {
    return {
      AttributeI: value,
    };
  }
  switch (typeof value) {
    case 'boolean':
      return {
        AttributeTF: value,
      };
    case 'string':
      return {
        AttributeB: Buffer.from(value),
      };
    case 'number':
      return {
        AttributeI: Long.fromInt(value),
      };
    default:
      return {
        AttributeB: value,
      };
  }
}

exports.getPubKeyBytesFromSPKI = function (spki) {
  return (Asn1ECPublicKey.decode(spki).point || {}).data;
};

exports.getPubKeyBytesFromDH = function (bytes) {
  return (Asn1DHPublicKey.decode(bytes).PublicKey || {}).data;
};

exports.authMetadata = function (metadata, instance, token) {
  metadata.add('authorization', `Bearer ${token}`);
  metadata.add('bluemix-instance', instance);

  return metadata;
};
