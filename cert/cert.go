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

func GeneratePrivateKeyfile(path string, keysize int) (*rsa.PrivateKey, error) {
	if key, err := rsa.GenerateKey(rand.Reader, keysize); err == nil {
		return key, ioutil.WriteFile(path, x509.MarshalPKCS1PrivateKey(key), DEFAULT_FILE_PERM)
	} else {
		return nil, err
	}
}

func CreateCert(path string, validYears int, cn string, signerKey *rsa.PrivateKey, clientCert bool, ca *x509.Certificate, key *rsa.PublicKey) (*x509.Certificate, error) {
	var signeeKey *rsa.PublicKey
	var signer *x509.Certificate
	isCa := ca == nil

	if isCa {
		signeeKey = &signerKey.PublicKey
	} else {
		signeeKey = key
	}

	if serial, serialErr := rand.Int(rand.Reader, big.NewInt(math.MaxInt64)); serialErr == nil {
		template := x509.Certificate{
			Subject: pkix.Name{
				CommonName: cn,
			},
			SerialNumber: serial,
			NotBefore:    time.Now(),
		}
		template.NotAfter = template.NotBefore.AddDate(validYears, 0, 0)

		if isCa {
			signer = &template
			template.IsCA = true
			template.KeyUsage = x509.KeyUsageCertSign
		} else {
			signer = ca
			template.KeyUsage = x509.KeyUsageDataEncipherment
			if clientCert {
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			} else {
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}
		}

		if cert, err := x509.CreateCertificate(rand.Reader, &template, signer, signeeKey, signerKey); err == nil {
			ioutil.WriteFile(path, cert, DEFAULT_FILE_PERM)
			return &template, nil
		} else {
			return nil, err
		}
	} else {
		return nil, serialErr
	}
}
