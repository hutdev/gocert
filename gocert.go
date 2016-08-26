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
	"io/ioutil"
	"log"
	"path"
)

const defaultKeysize = 2048
const defaultOutpath = "."
const defaultCaKeyName = "ca.key"
const defaultCertKeyName = "cert.key"
const restrictivePermissions = 0600

func GenerateKey(path string) (*rsa.PrivateKey, error) {
	if key, err := rsa.GenerateKey(rand.Reader, defaultKeysize); err == nil {
		return key, ioutil.WriteFile(path, x509.MarshalPKCS1PrivateKey(key), restrictivePermissions)
	} else {
		return nil, err
	}
}

func main() {
	outpath := defaultOutpath
	caKeyName := defaultCaKeyName
	caKeyPath := path.Join(outpath, caKeyName)
	certKeyName := defaultCertKeyName
	certKeyPath := path.Join(outpath, certKeyName)

	//Create a private key for the CA
	if _, err := GenerateKey(caKeyPath); err == nil {
		log.Printf("Private key stored at %s.\n", caKeyPath)
	} else {
		log.Fatal(err)
	}

	//Create a private key for the certificate
	if _, err := GenerateKey(certKeyPath); err == nil {
		log.Printf("Private key stored at %s.\n", certKeyPath)
	} else {
		log.Fatal(err)
	}
}
