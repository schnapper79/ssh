package ssh

import (
	"io/ioutil"
	"log"

	gossh "golang.org/x/crypto/ssh"
)

type ClientCertAuth struct {
	UserCaKeyPub   PublicKey
	loggingEnabled bool
}

func (ca *ClientCertAuth) ReadFile(filepath string) error {
	caCert, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}
	hc, _, _, _, err := ParseAuthorizedKey(caCert)
	if err != nil {
		return err
	}
	ca.UserCaKeyPub = hc
	return nil
}

func (ca *ClientCertAuth) CheckClientCert(ctx Context, key PublicKey) bool {
	validCert, ok := key.(*gossh.Certificate)
	if !ok {
		if ca.loggingEnabled {
			log.Printf("got (%T), want *Certificate", key)
		}
		return false
	}
	checker := new(gossh.CertChecker)

	err := checker.CheckCert(ctx.User(), validCert)
	if err != nil {
		if ca.loggingEnabled {
			log.Printf("error CertChecker: %v", err)
		}
		return false
	}

	if !KeysEqual(ca.UserCaKeyPub, validCert.SignatureKey) {
		if ca.loggingEnabled {
			fp := gossh.FingerprintSHA256(ca.UserCaKeyPub)
			sigFp := gossh.FingerprintSHA256(validCert.SignatureKey)
			log.Printf("fp soll: %v, ist: %v", fp, sigFp)
		}
		return false
	}

	return true
}
