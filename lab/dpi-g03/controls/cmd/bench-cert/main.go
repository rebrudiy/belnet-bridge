package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	directory := flag.String("directory", "", "new private artifact directory")
	hosts := flag.String("hosts", "bench-entry1.test,bench-entry2.test", "explicit lab SANs only")
	flag.Parse()
	if *directory == "" {
		log.Fatal("new directory required")
	}
	if _, err := os.Stat(*directory); !os.IsNotExist(err) {
		log.Fatal("refusing to overwrite private certificate directory")
	}
	names := strings.Split(*hosts, ",")
	for _, name := range names {
		if !strings.HasSuffix(name, ".test") {
			log.Fatal("lab cert names must end.test")
		}
	}
	if err := os.MkdirAll(*directory, 0700); err != nil {
		log.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	encodedKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*directory, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*directory, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encodedKey}), 0600); err != nil {
		log.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	hash := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"spki_sha256_base64": base64.StdEncoding.EncodeToString(hash[:]), "names": names, "system_trust_changed": false})
}
