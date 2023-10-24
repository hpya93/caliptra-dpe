// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/ecdsa"
	"crypto/x509"
	"math/big"
	"testing"
)

// This is one of E2E cases that adds tests for a very common Caliptra DPE flow
// It imitates a SoC manager performing SPDM Responder-like flow
// The client plays role of SPDM requestor and DPE plays the role of SPDM responder
// Client authenticates DPE by verifying digital signature of DPE and building a certificate chain
// for certificate holding the signing keys.
// According to SPDM specification, the authenticity of a Responder is determined by digital signatures.
// A Responder proves its identity by generating digital signatures using a private key,
// and the signatures can be cryptographically verified by the Requester using the public key.
// Hence, the verification makes use of Sign, CertifyKey and GetCertificateChain DPE commands to perform a similar verification.
// This is also the DPE attestation flow which ensures the client that DPE is authentsic.
func TestDPEInstanceAuthentication(d TestDPEInstance, c DPEClient, t *testing.T) {
	testDPEInstanceAuthentication(d, c, t)
}

func testDPEInstanceAuthentication(d TestDPEInstance, c DPEClient, t *testing.T) {
	ctx := &ContextHandle{0}
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("[FATAL]: Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()
	seqLabel := make([]byte, digestLen)
	for i := range seqLabel {
		seqLabel[i] = byte(i)
	}

	toBeSigned := make([]byte, digestLen)
	for i := range toBeSigned {
		toBeSigned[i] = byte(i)
	}

	// Get Digital Signature from DPE (responder)
	signResp := getDpeSignature(c, t, ctx, seqLabel, toBeSigned)

	// Get Public key from DPE (responder) to verify signature
	certifyKeyResp := getDpeSigningCert(c, t, ctx, seqLabel)

	// Validate certificate chain validation to establish the CA of signing key certificate
	leafCertBytes := certifyKeyResp.Certificate
	validateDpeCertChain(c, t, ctx, leafCertBytes)

	// Extract public key from DPE signing cert
	pub := extractPubKey(t, certifyKeyResp.Certificate)

	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Errorf("[ERROR]: public key is not an ECDSA key")
	}

	// Verify Signature created by DPE private key using Public key exposed in certificate
	verifySignature(publicKey, toBeSigned[:], signResp, t)
}

func verifySignature(publicKey *ecdsa.PublicKey, toBeSigned []byte, signResp *DPESignedHash, t *testing.T) {
	r1 := signResp.HmacOrSignatureR
	r := new(big.Int).SetBytes(r1)
	s1 := signResp.SignatureS
	s := new(big.Int).SetBytes(s1)
	valid := ecdsa.Verify(publicKey, toBeSigned[:], r, s)
	if valid {
		t.Logf("[LOG]: Validation result:verify sign, %v", valid)
	} else {
		t.Errorf("[ERROR]: validation result:verify sign failed, %v", valid)
	}
}

func getDpeSignature(c DPEClient, t *testing.T, ctx *ContextHandle, seqLabel []byte, toBeSigned []byte) *DPESignedHash {
	signParams := struct {
		Flags      SignFlags
		Label      []byte
		ToBeSigned []byte
	}{
		Flags:      SignFlags(0),
		Label:      seqLabel,
		ToBeSigned: toBeSigned,
	}

	// Get signed hash from DPE
	signResp, err := c.Sign(ctx, signParams.Label, signParams.Flags, signParams.ToBeSigned)
	if err != nil {
		t.Fatalf("[FATAL]: Could not sign: %v", err)
	}

	return signResp
}

func getDpeSigningCert(c DPEClient, t *testing.T, ctx *ContextHandle, signingLabel []byte) *CertifiedKey {
	certifyKeyParams := struct {
		Label []byte
		Flags CertifyKeyFlags
	}{
		Label: signingLabel,
		Flags: CertifyKeyFlags(0),
	}

	certifyKeyResp, err := c.CertifyKey(ctx, certifyKeyParams.Label, CertifyKeyX509, CertifyKeyFlags(0))
	if err != nil {
		t.Fatalf("[FATAL]: Could not CertifyKey: %v", err)
	}
	return certifyKeyResp
}

func validateDpeCertChain(c DPEClient, t *testing.T, ctx *ContextHandle, leafBytes []byte) {
	certificateChain, err := c.GetCertificateChain()
	if err != nil {
		t.Fatalf("[FATAL]: Could not get Certificate Chain: %v", err)
	}
	certChain := checkCertificateChain(t, certificateChain)

	leafCert, _ := x509.ParseCertificate(leafBytes)
	validateLeafCertChain(t, certChain, leafCert)
}
