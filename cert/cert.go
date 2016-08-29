/*
 * The MIT License
 *
 * Copyright 2016 <a href="mailto:hutdevelopment@gmail.com">hutdev</a>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"time"
)

const DEFAULT_FILE_PERM = 0600

type CertificateRequest struct {
	ValidYears           int
	CommonName           string
	SignerKey            *rsa.PrivateKey
	CertificateKey       *rsa.PublicKey
	ClientCert           bool
	CertificateAuthority *x509.Certificate
	EncodePEM            bool
}

func NewCertificateAuthorityRequest(validYears int, commonName string, privKey *rsa.PrivateKey, encodePem bool) *CertificateRequest {
	return &CertificateRequest{
		ValidYears: validYears,
		CommonName: commonName,
		SignerKey:  privKey,
		EncodePEM:  encodePem,
	}
}

func GeneratePrivateKeyfile(path string, keysize int) (*rsa.PrivateKey, error) {
	if key, err := rsa.GenerateKey(rand.Reader, keysize); err == nil {
		return key, ioutil.WriteFile(path, x509.MarshalPKCS1PrivateKey(key), DEFAULT_FILE_PERM)
	} else {
		return nil, err
	}
}

func GeneratePEMPrivateKeyfile(path string, keysize int) (key *rsa.PrivateKey, err error) {
	var pemblock *pem.Block
	var outfile *os.File

	if key, err = rsa.GenerateKey(rand.Reader, keysize); err == nil {
		if outfile, err = os.Create(path); err == nil {
			defer outfile.Close()
			outfile.Chmod(DEFAULT_FILE_PERM)
			pemblock = &pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			}
			err = pem.Encode(outfile, pemblock)
		}
	}
	return
}

func LoadPrivateKeyfile(path string) (key *rsa.PrivateKey, err error) {
	var raw []byte
	if raw, err = ioutil.ReadFile(path); err == nil {
		if pemblock, _ := pem.Decode(raw); pemblock == nil {
			key, err = x509.ParsePKCS1PrivateKey(raw)
		} else {
			key, err = x509.ParsePKCS1PrivateKey(pemblock.Bytes)
		}
	}
	return
}

func CreateCert(path string, csr *CertificateRequest) (template *x509.Certificate, err error) {
	var signeeKey *rsa.PublicKey
	var signer *x509.Certificate
	var pemblock *pem.Block
	var outfile *os.File
	var serial *big.Int
	var cert []byte
	isCa := csr.CertificateAuthority == nil

	if isCa {
		signeeKey = &csr.SignerKey.PublicKey
	} else {
		signeeKey = csr.CertificateKey
	}

	if serial, err = rand.Int(rand.Reader, big.NewInt(math.MaxInt64)); err == nil {
		template = &x509.Certificate{
			Subject: pkix.Name{
				CommonName: csr.CommonName,
			},
			SerialNumber: serial,
			NotBefore:    time.Now(),
		}
		template.NotAfter = template.NotBefore.AddDate(csr.ValidYears, 0, 0)

		if isCa {
			signer = template
			template.IsCA = true
			template.KeyUsage = x509.KeyUsageCertSign
		} else {
			signer = csr.CertificateAuthority
			template.KeyUsage = x509.KeyUsageDigitalSignature
			if csr.ClientCert {
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			} else {
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}
		}

		if cert, err = x509.CreateCertificate(rand.Reader, template, signer, signeeKey, csr.SignerKey); err == nil {
			if csr.EncodePEM {
				if outfile, err = os.Create(path); err == nil {
					defer outfile.Close()
					outfile.Chmod(DEFAULT_FILE_PERM)
					pemblock = &pem.Block{
						Type:  "CERTIFICATE",
						Bytes: cert,
					}
					err = pem.Encode(outfile, pemblock)
				}
			} else {
				err = ioutil.WriteFile(path, cert, DEFAULT_FILE_PERM)
			}
		}
	}
	return
}

func LoadCert(path string) (crt *x509.Certificate, err error) {
	var raw []byte
	if raw, err = ioutil.ReadFile(path); err == nil {
		if pemblock, _ := pem.Decode(raw); pemblock == nil {
			crt, err = x509.ParseCertificate(raw)
		} else {
			crt, err = x509.ParseCertificate(pemblock.Bytes)
		}
	}
	return
}
