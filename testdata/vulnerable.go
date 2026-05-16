package vulnerable

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
)

func badMD5(data []byte) [16]byte {
	return md5.Sum(data)
}

func badSHA1(data []byte) [20]byte {
	return sha1.Sum(data)
}

func badDES(key []byte) {
	_, _ = des.NewCipher(key)
}

func bad3DES(key []byte) {
	_, _ = des.NewTripleDESCipher(key)
}

func badRC4(key []byte) {
	_, _ = rc4.NewCipher(key)
}
