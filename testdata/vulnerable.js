const crypto = require('crypto');

function badMD5(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

function badSHA1(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

module.exports = { badMD5, badSHA1 };
