package vulnerablekeys

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
)

func weakRSA() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024)
}

func disallowedDSA() error {
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		return err
	}
	priv := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
	return dsa.GenerateKey(priv, rand.Reader)
}

// Secp256k1 (Bitcoin) curve — not on the FIPS 186-5 approved list.
const curveName = "secp256k1"
