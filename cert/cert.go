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
	"io/ioutil"
	"math"
	"math/big"
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
}

func NewCertificateAuthorityRequest(validYears int, commonName string, privKey *rsa.PrivateKey) *CertificateRequest {
	return &CertificateRequest{
		ValidYears: validYears,
		CommonName: commonName,
		SignerKey:  privKey,
	}
}

func GeneratePrivateKeyfile(path string, keysize int) (*rsa.PrivateKey, error) {
	if key, err := rsa.GenerateKey(rand.Reader, keysize); err == nil {
		return key, ioutil.WriteFile(path, x509.MarshalPKCS1PrivateKey(key), DEFAULT_FILE_PERM)
	} else {
		return nil, err
	}
}

func LoadPrivateKeyfile(path string) (*rsa.PrivateKey, error) {
	if b, err := ioutil.ReadFile(path); err == nil {
		return x509.ParsePKCS1PrivateKey(b)
	} else {
		return nil, err
	}
}

func CreateCert(path string, csr *CertificateRequest) (*x509.Certificate, error) {
	var signeeKey *rsa.PublicKey
	var signer *x509.Certificate
	isCa := csr.CertificateAuthority == nil

	if isCa {
		signeeKey = &csr.SignerKey.PublicKey
	} else {
		signeeKey = csr.CertificateKey
	}

	if serial, serialErr := rand.Int(rand.Reader, big.NewInt(math.MaxInt64)); serialErr == nil {
		template := x509.Certificate{
			Subject: pkix.Name{
				CommonName: csr.CommonName,
			},
			SerialNumber: serial,
			NotBefore:    time.Now(),
		}
		template.NotAfter = template.NotBefore.AddDate(csr.ValidYears, 0, 0)

		if isCa {
			signer = &template
			template.IsCA = true
			template.KeyUsage = x509.KeyUsageCertSign
		} else {
			signer = csr.CertificateAuthority
			template.KeyUsage = x509.KeyUsageDataEncipherment
			if csr.ClientCert {
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			} else {
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}
		}

		if cert, err := x509.CreateCertificate(rand.Reader, &template, signer, signeeKey, csr.SignerKey); err == nil {
			ioutil.WriteFile(path, cert, DEFAULT_FILE_PERM)
			return &template, nil
		} else {
			return nil, err
		}
	} else {
		return nil, serialErr
	}
}

func LoadCert(path string) (*x509.Certificate, error) {
	if b, err := ioutil.ReadFile(path); err == nil {
		return x509.ParseCertificate(b)
	} else {
		return nil, err
	}
}
