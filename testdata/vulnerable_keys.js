const crypto = require('crypto');

function weakRSA() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
}

function nonNistCurve() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
}

module.exports = { weakRSA, nonNistCurve };
