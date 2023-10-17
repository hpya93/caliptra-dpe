// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")

	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}
)

func TestTpmPolicySigning(d TestDPEInstance, c DPEClient, t *testing.T) {
	testTpmPolicySigning(d, c, t)
}

func startTpmSession(t *testing.T, tpm io.ReadWriteCloser) (tpmutil.Handle, []byte, error) {
	totalHandles := 0
	for _, handleType := range handleNames["all"] {
		handles, err := client.Handles(tpm, handleType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting handles %s: %v", *tpmPath, err)
			os.Exit(1)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(tpm, handle); err != nil {
				fmt.Fprintf(os.Stderr, "Error flushing handle 0x%x: %v", handle, err)
				os.Exit(1)
			}
			t.Logf("Handle 0x%x flushed", handle)
			totalHandles++
		}
	}

	sessHandle, nonce, err := tpm2.StartAuthSession(tpm, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		t.Fatalf("[FATAL]: StartAuthSession() failed: %v", err)
	}

	return sessHandle, nonce, nil
}

func testTpmPolicySigning(d TestDPEInstance, c DPEClient, t *testing.T) {
	var ctx ContextHandle = [16]byte{0}

	//Create tpm auth session to get nonce and form label which is digest
	tpm, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
	}

	sessHandle, nonce, err := startTpmSession(t, tpm)
	if err != nil {
		t.Fatalf("[FATAL]: Error in getting tpm nonce")
	}

	defer func() {
		if err := tpm.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "can't close TPM %s: %v", *tpmPath, err)
			os.Exit(1)
		}
	}()

	defer tpm2.FlushContext(tpm, sessHandle)

	// Build SignHash request
	expiry := []int32{math.MinInt32, math.MinInt32 + 1, -1, 0, 1, math.MaxInt32}
	digest := getDigest(nonce, expiry)

	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	seqLabel := make([]byte, digestLen)
	for i, _ := range seqLabel {
		seqLabel[i] = byte(i)
	}

	signParams := struct {
		Flags      SignFlags
		Label      []byte
		ToBeSigned []byte
	}{
		Flags:      SignFlags(0),
		Label:      seqLabel,
		ToBeSigned: digest[:],
	}

	// Get signed hash from DPE
	signResp, err := c.Sign(&ctx, signParams.Label, signParams.Flags, signParams.ToBeSigned)
	if err != nil {
		t.Fatalf("[FATAL]: Could not sign: %v", err)
	}

	// Get certificate chain of signing key
	certifyKeyParams := struct {
		Label []byte
		Flags CertifyKeyFlags
	}{
		Label: seqLabel,
		Flags: CertifyKeyFlags(0),
	}

	certifyKeyResp, err := c.CertifyKey(&(signResp.Handle), certifyKeyParams.Label, CertifyKeyX509, CertifyKeyFlags(0))
	if err != nil {
		t.Fatalf("[FATAL]: Could not CertifyKey: %v", err)
	}

	pubKey := extractPubKey(t, certifyKeyResp.Certificate)

	// Get TPM handle loaded with public key
	pkh := getPubKeyHandle(t, pubKey, tpm)

	// Get encoded signature from TPM
	rBytes := [32]byte(signResp.HmacOrSignatureR)
	r := new(big.Int).SetBytes(rBytes[:])
	sBytes := [32]byte(signResp.SignatureS)
	s := new(big.Int).SetBytes(sBytes[:])

	encodedSignature := getEncodedSignature(t, r, s)

	// Verify Policy with Signature
	_, _, err = tpm2.PolicySigned(tpm, pkh, sessHandle, nonce, nil, nil, expiry[0], encodedSignature)
	if err != nil {
		t.Fatalf("[FATAL]: PolicySigned() failed: %v", err)
	}

	t.Log("[LOG]: PolicySigned() call success")
}

func getDigest(nonce []byte, expiry []int32) [32]byte {

	expBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expBytes, uint32(expiry[0]))

	toDigest := append(nonce, expBytes...)

	digest := sha256.Sum256(toDigest)
	return digest
}

func extractPubKey(t *testing.T, leafBytes []byte) any {
	var x509Cert *x509.Certificate
	var err error

	t.Log("[LOG]: Parse the obtained certificate...")
	// Check whether certificate is DER encoded.
	if x509Cert, err = x509.ParseCertificate(leafBytes); err != nil {
		t.Fatalf("[FATAL]: Could not parse certificate using crypto/x509: %v", err)
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
	if err != nil {
		t.Fatalf("[FATAL]: Could not marshal pub key: %v", err)
	}

	// Parse the DER-encoded public key
	pubKey, err := x509.ParsePKIXPublicKey(publicKeyDer)
	if err != nil {
		t.Fatalf("[FATAL]: Failed to parse DER-encoded public key: %v", err)
	}

	return pubKey
}

func getPubKeyHandle(t *testing.T, pubKey any, tpm io.ReadWriteCloser) tpmutil.Handle {
	var tpmPublic tpm2.Public

	// Create a tpm2.Public structure from the parsed ECDSA public key
	switch pubKey := pubKey.(type) {
	case *ecdsa.PublicKey:
		tpmPublic = tpm2.Public{
			Type:       tpm2.AlgECC, // ECDSA key type
			NameAlg:    tpm2.AlgSHA256,
			Attributes: tpm2.FlagSign | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
			ECCParameters: &tpm2.ECCParams{
				Sign: &tpm2.SigScheme{
					Alg:  tpm2.AlgECDSA,
					Hash: tpm2.AlgSHA256,
				},
				CurveID: tpm2.CurveNISTP256,
				Point: tpm2.ECPoint{
					XRaw: new(big.Int).SetBytes(pubKey.X.Bytes()).Bytes(),
					YRaw: new(big.Int).SetBytes(pubKey.Y.Bytes()).Bytes(),
				},
			},
		}
	default:
		t.Fatalf("[FATAL]: Unsupported public key type")
	}

	t.Logf("[LOG]: TPM2 Public Key: %v", tpmPublic)

	pkh, _, err := tpm2.LoadExternal(tpm, tpmPublic, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		t.Fatalf("[FATAL]: Unable to load eexternal public key. Error: %v", err)
	}

	return pkh
}

func getEncodedSignature(t *testing.T, r *big.Int, s *big.Int) []byte {
	signature := tpm2.Signature{
		Alg: tpm2.AlgECDSA,
		ECC: &tpm2.SignatureECC{
			HashAlg: tpm2.AlgSHA256,
			R:       r,
			S:       s,
		},
	}
	encodedSign, err := signature.Encode()
	if err != nil {
		t.Fatalf("[FATAL]: Unable to encode signature: %v", err)
	}
	t.Logf("[LOG]: Encoded Signature is %s", string(encodedSign))

	return encodedSign
}
