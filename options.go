package ssh

import (
	"io/ioutil"

	gossh "golang.org/x/crypto/ssh"
)

// PasswordAuth returns a functional option that sets PasswordHandler on the server.
func PasswordAuth(fn PasswordHandler) Option {
	return func(srv *Server) error {
		srv.PasswordHandler = fn
		return nil
	}
}

// PublicKeyAuth returns a functional option that sets PublicKeyHandler on the server.
func PublicKeyAuth(fn PublicKeyHandler) Option {
	return func(srv *Server) error {
		srv.PublicKeyHandler = fn
		return nil
	}
}

// HostKeyFile returns a functional option that adds HostSigners to the server
// from a PEM file at filepath.
func HostKeyFile(filepath string) Option {
	return func(srv *Server) error {
		pemBytes, err := ioutil.ReadFile(filepath)
		if err != nil {
			return err
		}

		signer, err := gossh.ParsePrivateKey(pemBytes)
		if err != nil {
			return err
		}

		srv.AddHostKey(signer)

		return nil
	}
}

// HostKeyFile returns a functional option that adds HostSigners to the server
// from a PEM file at filepath.
func HostKeyFileWithCert(filepathKey, filepathCert string) Option {
	return func(srv *Server) error {
		pemBytes, err := ioutil.ReadFile(filepathKey)
		if err != nil {
			return err
		}

		certBytes, err := ioutil.ReadFile(filepathCert)
		if err != nil {
			return err
		}

		signer, err := gossh.ParsePrivateKey(pemBytes)
		if err != nil {
			return err
		}

		certPubKey, _, _, _, err := gossh.ParseAuthorizedKey(certBytes)
		if err != nil {
			return err
		}
		validCert, ok := certPubKey.(*gossh.Certificate)
		if !ok {
			return err
		}

		certSigner, err := gossh.NewCertSigner(validCert, signer)

		srv.AddHostKey(certSigner)

		return nil
	}
}

// HostKeyFile returns a functional option that adds HostSigners to the server
// from a PEM file at filepath.
func HostKeyWithCertFromRaw(rawKey, rawCert []byte) Option {
	return func(srv *Server) error {
		signer, err := gossh.ParsePrivateKey(rawKey)
		if err != nil {
			return err
		}

		certPubKey, _, _, _, err := gossh.ParseAuthorizedKey(rawCert)
		if err != nil {
			return err
		}
		validCert, ok := certPubKey.(*gossh.Certificate)
		if !ok {
			return err
		}

		certSigner, err := gossh.NewCertSigner(validCert, signer)

		srv.AddHostKey(certSigner)

		return nil
	}
}

func KeyboardInteractiveAuth(fn KeyboardInteractiveHandler) Option {
	return func(srv *Server) error {
		srv.KeyboardInteractiveHandler = fn
		return nil
	}
}

// HostKeyPEM returns a functional option that adds HostSigners to the server
// from a PEM file as bytes.
func HostKeyPEM(bytes []byte) Option {
	return func(srv *Server) error {
		signer, err := gossh.ParsePrivateKey(bytes)
		if err != nil {
			return err
		}

		srv.AddHostKey(signer)

		return nil
	}
}

// NoPty returns a functional option that sets PtyCallback to return false,
// denying PTY requests.
func NoPty() Option {
	return func(srv *Server) error {
		srv.PtyCallback = func(ctx Context, pty Pty) bool {
			return false
		}
		return nil
	}
}

// WrapConn returns a functional option that sets ConnCallback on the server.
func WrapConn(fn ConnCallback) Option {
	return func(srv *Server) error {
		srv.ConnCallback = fn
		return nil
	}
}
