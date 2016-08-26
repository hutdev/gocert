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
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"os"
	"path"
	"time"
)

const defaultKeysize = 2048
const defaultCAAge = 10
const defaultCertAge = 3
const defaultOutpath = "."
const defaultCaKeyName = "ca.key"
const defaultCaCertName = "ca.crt"
const defaultCertKeyName = "server.key"
const defaultCertName = "server.crt"
const restrictivePermissions = 0600

var outpath string
var commonName string
var caCommonName string

func init() {
	const cnUsage = "Value for the common name (CN) field"
	const cnFlag = "cn"
	const caCnUsage = "Value for the common name (CN) field of the certificate authority (CA)"
	const caCnFlag = "cacn"

	flag.StringVar(&outpath, "out", defaultOutpath, "Output directory")

	if hostname, err := os.Hostname(); err == nil {
		flag.StringVar(&commonName, cnFlag, hostname, cnUsage)
		flag.StringVar(&caCommonName, caCnFlag, hostname, caCnUsage)
	} else {
		flag.StringVar(&commonName, cnFlag, "dummy", cnUsage)
		flag.StringVar(&caCommonName, caCnFlag, "dummyCA", caCnUsage)
	}
	flag.Parse()
}

func GenerateKey(path string) (*rsa.PrivateKey, error) {
	if key, err := rsa.GenerateKey(rand.Reader, defaultKeysize); err == nil {
		return key, ioutil.WriteFile(path, x509.MarshalPKCS1PrivateKey(key), restrictivePermissions)
	} else {
		return nil, err
	}
}

func CreateCert(path string, cn string, signerKey *rsa.PrivateKey, ca *x509.Certificate, key *rsa.PublicKey) (*x509.Certificate, error) {
	var signeeKey *rsa.PublicKey
	var signer *x509.Certificate
	var certAge int
	isCa := ca == nil

	if isCa {
		signeeKey = &signerKey.PublicKey
		certAge = defaultCAAge
	} else {
		signeeKey = key
		certAge = defaultCertAge
	}

	if serial, serialErr := rand.Int(rand.Reader, big.NewInt(math.MaxInt64)); serialErr == nil {
		template := x509.Certificate{
			Subject: pkix.Name{
				CommonName: cn,
			},
			SerialNumber: serial,
			NotBefore:    time.Now(),
		}
		template.NotAfter = template.NotBefore.AddDate(certAge, 0, 0)

		if isCa {
			signer = &template
			template.IsCA = true
			template.KeyUsage = x509.KeyUsageCertSign
		} else {
			signer = ca
			template.KeyUsage = x509.KeyUsageDataEncipherment
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}

		if cert, err := x509.CreateCertificate(rand.Reader, &template, signer, signeeKey, signerKey); err == nil {
			ioutil.WriteFile(path, cert, restrictivePermissions)
			return &template, nil
		} else {
			return nil, err
		}
	} else {
		return nil, serialErr
	}
}

func main() {
	caKeyName := defaultCaKeyName
	caKeyPath := path.Join(outpath, caKeyName)
	caCertName := defaultCaCertName
	caCertPath := path.Join(outpath, caCertName)
	certKeyName := defaultCertKeyName
	certKeyPath := path.Join(outpath, certKeyName)
	certName := defaultCertName
	certPath := path.Join(outpath, certName)
	var caKey, certKey *rsa.PrivateKey
	var caCert *x509.Certificate
	var err error

	//Create a private key for the CA
	if caKey, err = GenerateKey(caKeyPath); err == nil {
		log.Printf("Private key stored at %s.\n", caKeyPath)
	} else {
		log.Fatal(err)
	}

	//Create a private key for the certificate
	if certKey, err = GenerateKey(certKeyPath); err == nil {
		log.Printf("Private key stored at %s.\n", certKeyPath)
	} else {
		log.Fatal(err)
	}

	//Create a self-signed CA certificate
	if caCert, err = CreateCert(caCertPath, caCommonName, caKey, nil, nil); err == nil {
		log.Printf("CA certificate stored at %s.\n", caCertPath)
	} else {
		log.Fatal(err)
	}

	//Create a server certificate
	if _, err = CreateCert(certPath, commonName, caKey, caCert, &certKey.PublicKey); err == nil {
		log.Printf("Server certificate stored at %s.\n", certPath)
	} else {
		log.Fatal(err)
	}
}
