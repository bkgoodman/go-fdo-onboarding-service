// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// bmo_test_helper generates COSE keys and signed meta-payloads for BMO
// integration testing. It outputs files to a specified directory.
//
// Usage:
//
//	go run ./tests/bmo_test_helper -dir <output_dir> -mode <mode> [options]
//
// Modes:
//
//	gen-key        Generate COSE_Key (CBOR) for meta-payload signing
//	gen-meta       Generate a CBOR MetaPayload (unsigned)
//	sign-meta      Sign a CBOR MetaPayload with COSE Sign1
//	sign-meta-wrong Sign a CBOR MetaPayload with a DIFFERENT key (for negative testing)
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

func main() {
	dir := flag.String("dir", ".", "Output directory")
	mode := flag.String("mode", "", "Mode: gen-key, gen-meta, sign-meta, sign-meta-wrong")

	// MetaPayload fields
	mimeType := flag.String("mime", "application/x-iso9660-image", "Image MIME type")
	imageURL := flag.String("image-url", "", "Image URL for meta-payload")
	imageName := flag.String("image-name", "test-image", "Image name")
	hashAlg := flag.String("hash-alg", "sha256", "Hash algorithm")

	// Key/payload files
	privKeyFile := flag.String("privkey", "", "Private key file (CBOR COSE_Key with d param, for sign-meta)")
	metaFile := flag.String("meta", "", "MetaPayload file (CBOR, for sign-meta)")

	flag.Parse()

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatalf("failed to create dir: %v", err)
	}

	switch *mode {
	case "gen-key":
		genKey(*dir)
	case "gen-meta":
		genMeta(*dir, *mimeType, *imageURL, *imageName, *hashAlg)
	case "sign-meta":
		signMeta(*dir, *privKeyFile, *metaFile, false)
	case "sign-meta-wrong":
		signMeta(*dir, *privKeyFile, *metaFile, true)
	case "gen-key-and-sign":
		// Convenience: generate key, meta, and signed meta in one shot
		genKey(*dir)
		genMeta(*dir, *mimeType, *imageURL, *imageName, *hashAlg)
		privPath := filepath.Join(*dir, "privkey.cbor")
		metaPath := filepath.Join(*dir, "meta.cbor")
		signMeta(*dir, privPath, metaPath, false)
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %q\n", *mode)
		fmt.Fprintf(os.Stderr, "Modes: gen-key, gen-meta, sign-meta, sign-meta-wrong, gen-key-and-sign\n")
		os.Exit(1)
	}
}

func genKey(dir string) {
	privKey, pubBytes, privBytes := generateKeyPair()
	_ = privKey // used in gen-key-and-sign flow

	pubPath := filepath.Join(dir, "signer.cbor")
	privPath := filepath.Join(dir, "privkey.cbor")

	if err := os.WriteFile(pubPath, pubBytes, 0o600); err != nil {
		log.Fatalf("failed to write %s: %v", pubPath, err)
	}
	if err := os.WriteFile(privPath, privBytes, 0o600); err != nil {
		log.Fatalf("failed to write %s: %v", privPath, err)
	}

	fmt.Printf("Generated COSE_Key (public): %s (%d bytes)\n", pubPath, len(pubBytes))
	fmt.Printf("Generated COSE_Key (private): %s (%d bytes)\n", privPath, len(privBytes))
}

// generateKeyPair creates an ECDSA P-256 key pair and returns the Go key,
// the CBOR-encoded public COSE_Key, and the CBOR-encoded private COSE_Key.
func generateKeyPair() (*ecdsa.PrivateKey, []byte, []byte) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}

	// Public COSE_Key (for verification)
	cosePub, err := cose.NewKey(privKey.Public())
	if err != nil {
		log.Fatalf("failed to create public COSE_Key: %v", err)
	}
	pubBytes, err := cbor.Marshal(cosePub)
	if err != nil {
		log.Fatalf("failed to marshal public COSE_Key: %v", err)
	}

	// Private COSE_Key (for signing) — clone public key map and add d parameter
	cosePriv := make(cose.Key)
	for k, v := range cosePub {
		cosePriv[k] = v
	}
	// Pad d to curve byte length
	dBytes := privKey.D.Bytes()
	byteLen := (privKey.Curve.Params().BitSize + 7) / 8
	if len(dBytes) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(dBytes):], dBytes)
		dBytes = padded
	}
	cosePriv[cose.KeyLabel{Int64: -4}] = dBytes
	privBytes, err := cbor.Marshal(cosePriv)
	if err != nil {
		log.Fatalf("failed to marshal private COSE_Key: %v", err)
	}

	return privKey, pubBytes, privBytes
}

func genMeta(dir, mimeType, imageURL, imageName, hashAlg string) {
	// Build MetaPayload as CBOR map with integer keys (per fdo.bmo.md)
	mp := map[int]any{
		0: mimeType,
		1: imageURL,
	}
	if hashAlg != "" {
		mp[3] = hashAlg
	}
	if imageName != "" {
		mp[6] = imageName
	}

	data, err := cbor.Marshal(mp)
	if err != nil {
		log.Fatalf("failed to marshal MetaPayload: %v", err)
	}

	metaPath := filepath.Join(dir, "meta.cbor")
	if err := os.WriteFile(metaPath, data, 0o600); err != nil {
		log.Fatalf("failed to write %s: %v", metaPath, err)
	}

	fmt.Printf("Generated MetaPayload: %s (%d bytes)\n", metaPath, len(data))
}

func signMeta(dir, privKeyFile, metaFile string, useWrongKey bool) {
	// Load the meta-payload
	metaData, err := os.ReadFile(metaFile)
	if err != nil {
		log.Fatalf("failed to read meta file %q: %v", metaFile, err)
	}

	var privKey *ecdsa.PrivateKey

	if useWrongKey {
		// Generate a completely different key for signing (negative test)
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("failed to generate wrong key: %v", err)
		}
	} else {
		// Load private key from CBOR COSE_Key and extract Go private key
		privKeyData, err := os.ReadFile(privKeyFile)
		if err != nil {
			log.Fatalf("failed to read private key %q: %v", privKeyFile, err)
		}
		var coseKey cose.Key
		if err := cbor.Unmarshal(privKeyData, &coseKey); err != nil {
			log.Fatalf("failed to unmarshal COSE_Key: %v", err)
		}
		// Extract public key and d parameter to reconstruct *ecdsa.PrivateKey
		pubKey, err := coseKey.Public()
		if err != nil {
			log.Fatalf("failed to extract public key: %v", err)
		}
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			log.Fatalf("expected *ecdsa.PublicKey, got %T", pubKey)
		}
		// Get d parameter from COSE_Key map
		dVal, ok := coseKey[cose.KeyLabel{Int64: -4}]
		if !ok {
			log.Fatalf("COSE_Key has no private d parameter")
		}
		dBytes, ok := dVal.([]byte)
		if !ok {
			log.Fatalf("d parameter is not []byte")
		}
		privKey = &ecdsa.PrivateKey{
			PublicKey: *ecPub,
			D:         new(big.Int).SetBytes(dBytes),
		}
	}

	// Create COSE Sign1 structure
	s1 := cose.Sign1[[]byte, []byte]{
		Payload: cbor.NewByteWrap(metaData),
	}
	if err := s1.Sign(privKey, nil, nil, nil); err != nil {
		log.Fatalf("failed to sign: %v", err)
	}

	// Marshal as tagged COSE_Sign1
	tagged := s1.Tag()
	signedData, err := cbor.Marshal(tagged)
	if err != nil {
		log.Fatalf("failed to marshal Sign1Tag: %v", err)
	}

	outName := "signed_meta.cbor"
	if useWrongKey {
		outName = "signed_meta_wrong.cbor"
	}
	outPath := filepath.Join(dir, outName)
	if err := os.WriteFile(outPath, signedData, 0o600); err != nil {
		log.Fatalf("failed to write %s: %v", outPath, err)
	}

	fmt.Printf("Signed MetaPayload (%s key): %s (%d bytes)\n",
		map[bool]string{true: "WRONG", false: "correct"}[useWrongKey],
		outPath, len(signedData))
}
