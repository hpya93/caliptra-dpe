// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	zx509 "github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	"golang.org/x/exp/slices"
)

type CertifyKeyFlag int

const (
	// RESERVED_0 CertifyKeyFlag = 31
	ADD_IS_CA CertifyKeyFlag = 30
	// RESERVED_1 CertifyKeyFlag     = 29:0   for future use

)

// This file is used to test the certify key command by using a simulator/emulator
var (
	ExtensionAuthorityKeyIdentifier = "2.5.29.35"           // OID for authority key identifier extension
	ExtensionBasicConstraints       = "2.5.29.19"           // OID for Basic Constraints extension
	ExtensionExtKeyUsage            = "2.5.29.37"           // OID for ExtKeyUsage extension
	ExtensionTcgDiceUeid            = "2.23.133.5.4.4"      // OID for tcg-dice-Ueid extension
	ExtensionTcgDiceMultiTcbInfo    = "2.23.133.5.4.5"      // OID for tcg-dice-MultiTcbInfo extension
	ExtensionTcgDiceKpIdentityInit  = "2.23.133.5.4.100.6"  // OID for tcg-dice-kp-identityInit
	ExtensionTcgDiceKpIdentityLoc   = "2.23.133.5.4.100.7"  // OID for tcg-dice-kp-identityLoc
	ExtensionTcgDiceKpAttestInit    = "2.23.133.5.4.100.8"  // OID for tcg-dice-kp-attestInit
	ExtensionTcgDiceKpAttestLoc     = "2.23.133.5.4.100.9"  // OID for tcg-dice-kp-attestLoc
	ExtensionTcgDiceKpAssertInit    = "2.23.133.5.4.100.10" // OID for tcg-dice-kp-assertInit
	ExtensionTcgDiceKpAssertLoc     = "2.23.133.5.4.100.11" // OID for tcg-dice-kp-assertLoc
	ExtensionTcgDiceKpEca           = "2.23.133.5.4.100.12" // OID for tcg-dice-kp-eca
)

var TCG_DICE_CRITICAL_EXTENSIONS = [...]string{
	ExtensionTcgDiceMultiTcbInfo,
	ExtensionTcgDiceUeid,
	ExtensionTcgDiceKpIdentityLoc,
	ExtensionTcgDiceKpAttestLoc,
}

var certifyKeyReq CertifyKeyReq[SHA256Digest]

type FWID struct {
	HashAlg asn1.ObjectIdentifier `asn1:"hashAlg,tag:0,implicit,optional"`
	Digest  []byte                `asn1:"digest,tag:1,implicit,optional"`
}

type DiceTcbInfo struct {
	Vendor string `asn1:"vendor,tag:0,implicit,optional"`
	Model  string `asn1:"model,tag:1,implicit,optional"`
	SVN    int    `asn1:"svn,tag:2,implicit,optional"`
	FWIDs  []FWID `asn1:"fwids,tag:3,implicit,optional"`
	Flags  int    `asn1:"flags,tag:4,implicit,optional"`
}

type MultiTcbInfo struct {
	DiceTcbInfos []DiceTcbInfo `asn1:"set"`
}

func TestCertifyKey(t *testing.T) {

	supportNeeded := []string{"AutoInit", "X509"}
	instance, err := GetTestTarget(supportNeeded)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestCertifyKey command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}
	testCertifyKey(instance, t)
}

func TestCertifyKey_SimulationMode(t *testing.T) {

	supportNeeded := []string{"AutoInit", "Simulation", "X509"}
	instance, err := GetTestTarget(supportNeeded)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestCertifyKey_SimulationMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}
	testCertifyKey(instance, t)
}

// Ignores critical extensions that are unknown to x509 package
// but atleast defined in DPE certificate profile specification.
// UnhandledCriticalExtensions may have only custom extensions mentioned in spec
// unknownExtnMap collects extensions unknown to both x59 and the DICE certificate profiles spec.
// positive case expects the unknownExtnMap to be empty.
func removeTcgDiceCriticalExtensions(t *testing.T, certs []*x509.Certificate) {
	t.Helper()
	unknownExtnMap := map[string][]string{}
	for _, cert := range certs {
		if len(cert.UnhandledCriticalExtensions) > 0 {
			unknownExtns := []string{}
			for _, extn := range cert.UnhandledCriticalExtensions {
				if !slices.Contains(TCG_DICE_CRITICAL_EXTENSIONS[:], extn.String()) {
					unknownExtns = append(unknownExtns, extn.String())
				}
			}

			if len(unknownExtnMap) == 0 {
				cert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}
			} else {
				unknownExtnMap[cert.Subject.String()] = unknownExtns
			}
		}
	}
	// The error details in thi map will be logged
	if len(unknownExtnMap) > 0 {
		for certSubject, ext := range unknownExtnMap {
			t.Errorf("Certificate \"%s\" has unhandled critical extension \"%s\"", certSubject, ext)
		}
		t.Fatalf("Cannot proceed certificate chain validation with non-empty unhandled critical extensions list")
	}
}

func checkCertifyKeyTcgDiceExtensions(t *testing.T, c *x509.Certificate) {
	t.Helper()

	// Check UEID extension
	checkCertifyKeyTcgUeidExtension(t, c)

	// Check MultiTcbInfo Extension
	checkCertifyKeyMultiTcbInfoExtension(t, c)
}

// A tcg-dice-Ueid extension MUST be added
// This SHALL be populated by the LABEL input parameter to CertifyKey
// The extension SHOULD be marked as critical
func checkCertifyKeyTcgUeidExtension(t *testing.T, c *x509.Certificate) {
	t.Helper()

	isFound := false
	// Check UEID extension
	for _, ext := range c.Extensions {
		if ext.Id.String() == ExtensionTcgDiceUeid {
			isFound = true
			if !ext.Critical {
				t.Fatalf("tcg-dice-Ueid extension is NOT marked as CRITICAL")
			}
			tcgDiceUEIDString := string(ext.Value)
			stringSlice := make([]string, len(certifyKeyReq.Label))
			for i, v := range certifyKeyReq.Label {
				stringSlice[i] = fmt.Sprintf("%v", v)
			}
			certifyKeyReqString := strings.Join(stringSlice, ", ")
			if tcgDiceUEIDString != certifyKeyReqString {
				// TODO: Fail when it is exected to pass
				t.Logf("tcg-dice-Ueid value does not match with the \"Label\" passed in CertifyKeyRequest")
			}
			break
		}
	}
	if !isFound {
		t.Fatalf("tcg-dice-Ueid extension is missing")
	}
}

// A tcg-dice-MultiTcbInfo extension.
// This extension SHOULD be marked as critical.
func checkCertifyKeyMultiTcbInfoExtension(t *testing.T, c *x509.Certificate) {
	t.Helper()

	// Check MultiTcbInfo Extension
	//tcg-dice-MultiTcbInfo extension
	var multiTcbInfo MultiTcbInfo
	for _, ext := range c.Extensions {
		if ext.Id.String() == ExtensionTcgDiceMultiTcbInfo { // OID for Tcg Dice MultiTcbInfo
			if !ext.Critical {
				t.Fatalf("TCG DICE MultiTcbInfo extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &multiTcbInfo)
			if err != nil {
				// TODO: Fail when expected to pass
				t.Logf("Failed to unmarshal MultiTcbInfo field: %v", err)
			}
			break
		}
	}
}

// Check whether certificate extended key usage is as per spec
// OID for ExtendedKeyUsage Extension: 2.5.29.37
// The ExtendedKeyUsage extension SHOULD be marked as critical
// If IsCA = true, the extension SHOULD contain tcg-dice-kp-eca
// If IsCA = false, the extension SHOULD contain tcg-dice-kp-attestLoc
func checkCertifyKeyExtendedKeyUsages(t *testing.T, c *x509.Certificate) {
	t.Helper()

	extKeyUsage := []asn1.ObjectIdentifier{}

	for _, ext := range c.Extensions {
		if ext.Id.String() == ExtensionExtKeyUsage { // OID for ExtKeyUsage extension
			// Extract the OID value from the extension
			_, err := asn1.Unmarshal(ext.Value, &extKeyUsage)
			if err != nil {
				t.Fatalf("Failed to unmarshal the Extended Key Usage extension: %v", err)
			}

			if !ext.Critical {
				t.Fatalf("The Extended Key Usage extension IS NOT CRITICAL, MUST BE CRITICAL")
			} else {
				t.Logf("The Extended Key Usage extension is marked CRITICAL")
			}
			break
		}
	}

	if len(extKeyUsage) == 0 {
		t.Fatalf("The Extended Key Usage extension is empty")
	}

	// Iterate over the OIDs in the ExtKeyUsage extension
	isExtendedKeyUsageValid := false
	if c.IsCA {
		for _, oid := range extKeyUsage {
			if oid.String() == ExtensionTcgDiceKpEca {
				isExtendedKeyUsageValid = true
				t.Logf("CA Certificate contains tcg-dice-kp-eca extended key usage")
				break
			}
		}
		if !isExtendedKeyUsageValid {
			t.Fatalf("CA Certificate does not contain tcg-dice-kp-eca extended key usage")
		}
	} else {
		for _, oid := range extKeyUsage {
			if oid.String() == ExtensionTcgDiceKpAttestLoc {
				isExtendedKeyUsageValid = true
				t.Logf("Certificate contains tcg-dice-kp-attestLoc extended key usage")
				break
			}
		}
		if !isExtendedKeyUsageValid {
			t.Fatalf("Certificate does not contain tcg-dice-kp-attestLoc extended key usage")
		}
	}
}

// Check whether certificate is valid, else log details of the issues found.
func checkCertificateValidity(t *testing.T, c *x509.Certificate) {
	t.Helper()

	// Check if the certificate is currently valid - this is checked internally in x509.Verify()
	now := time.Now().UTC()
	if now.Before(c.NotBefore) {
		t.Fatalf("Certificate is not valid yet, current time : %s, not before: %s", now, c.NotBefore)
	} else if now.After(c.NotAfter) {
		t.Fatalf("Certificate is expired, current time : %s, not after: %s", now, c.NotAfter)
	}
}

// The KeyUsage extension MUST contain only DigitalSignature
// If IsCA, KeyUsage extension MUST contain DigitalSignature and KeyCertSign
func checkCertifyKeyExtensions(t *testing.T, c *x509.Certificate) {
	t.Helper()

	//Check for keyusage extension
	if c.IsCA {
		allowedKeyUsages := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		certKeyUsageList := getKeyUsageNames(c.KeyUsage)
		allowedKeyUsageList := getKeyUsageNames(allowedKeyUsages)

		if c.KeyUsage == allowedKeyUsages {
			t.Logf("The CA Certificate has ONLY the expected key usage %v ", certKeyUsageList)
		} else {
			t.Fatalf("The CA Certificate has got %v but want %v ", certKeyUsageList, allowedKeyUsageList)
		}
	} else {
		allowedKeyUsages := x509.KeyUsageDigitalSignature
		certKeyUsageList := getKeyUsageNames(c.KeyUsage)
		allowedKeyUsageList := getKeyUsageNames(allowedKeyUsages)

		if c.KeyUsage == allowedKeyUsages {
			t.Logf("The leaf Certificate has ONLY the expected key usage %v ", certKeyUsageList)
		} else {
			t.Fatalf("The leaf Certificate has got %v but want %v ", certKeyUsageList, allowedKeyUsageList)
		}
	}
}

// Validate basic constraints in certificate returned by CertifyKey command
// against the flag set for input parameter.
// The BasicConstraints extension MUST be included
// If CertifyKey ADD_IS_CA is set, IsCA MUST be set to true.
// If CertifyKey ADD_IS_CA is NOT set, IsCA MUST be set to false
func checkCertifyKeyBasicConstraints(t *testing.T, c *x509.Certificate) {
	t.Helper()

	flagsBuf := &bytes.Buffer{}
	binary.Write(flagsBuf, binary.LittleEndian, certifyKeyReq.Flags)

	flagIsCA := extractFlagBit(int(ADD_IS_CA), uint32(certifyKeyReq.Flags))

	if flagIsCA == c.IsCA {
		t.Logf("ADD_IS_CA is set to %v and the basic constraint IsCA is set to %v", flagIsCA, c.IsCA)
	} else {
		// Fail when ADD_IS_CA flag is set properly in input parameters
		t.Logf("ADD_IS_CA is set to %v but the basic constraint IsCA is set to %v", flagIsCA, c.IsCA)
	}
}

// Validate X509 fields in certificate returned by CertifyKey command.
func validateCertifyKeyFields(t *testing.T, c *x509.Certificate) {
	t.Helper()

	// Check certificate lifetime
	checkCertificateValidity(t, c)

	// Check for basic constraints extension
	checkCertifyKeyBasicConstraints(t, c)

	// Check key usage extensions - DigitalSignature, KeyCertSign
	checkCertifyKeyExtensions(t, c)

	// Check extended key usage extensions
	checkCertifyKeyExtendedKeyUsages(t, c)

	// Check critical TCG extensions
	checkCertifyKeyTcgDiceExtensions(t, c)

}

func checkCertificateStructure(t *testing.T, certBytes []byte) *x509.Certificate {
	t.Helper()
	failed := false

	var x509Cert *x509.Certificate
	var err error

	// Check whether certificate is DER encoded.
	if x509Cert, err = x509.ParseCertificate(certBytes); err != nil {
		t.Fatalf("Could not parse certificate using crypto/x509: %v", err)
	}

	// Parse the cert with zcrypto so we can lint it.
	cert, err := zx509.ParseCertificate(certBytes)
	if err != nil {
		t.Errorf("Could not parse certificate using zcrypto/x509: %v", err)
		failed = true
	}

	// zlint provides a lot of linter sources. Limit results to just the relevant RFCs.
	// For a full listing of supported linter sources, see https://github.com/zmap/zlint/blob/master/v3/lint/source.go
	registry, err := lint.GlobalRegistry().Filter(lint.FilterOptions{
		IncludeSources: lint.SourceList{
			lint.RFC3279,
			lint.RFC5280,
			lint.RFC5480,
			lint.RFC5891,
			lint.RFC8813,
		}})
	if err != nil {
		t.Fatalf("Could not set up zlint registry: %v", err)
	}

	results := zlint.LintCertificateEx(cert, registry)

	for id, result := range results.Results {
		var level string
		switch result.Status {
		case lint.Error:
			level = "ERROR"
		case lint.Warn:
			level = "WARN"
		default:
			continue
		}
		details := result.Details
		if details != "" {
			details = fmt.Sprintf("%s. ", details)
		}
		l := registry.ByName(id)
		// TODO(https://github.com/chipsalliance/caliptra-dpe/issues/74):
		// Fail the test with Errorf here once we expect it to pass.
		t.Logf("[%s] %s: %s%s (%s)", level, l.Source, details, l.Description, l.Citation)
		failed = true
	}

	if failed {
		// Dump the cert in PEM and hex for use with various tools
		t.Logf("Offending certificate (PEM):\n%s", (string)(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		})))
		t.Logf("Offending certificate (DER):\n%x", certBytes)
	}
	return x509Cert
}

func testCertifyKey(d TestDPEInstance, t *testing.T) {
	if d.HasPowerControl() {
		err := d.PowerOn()
		if err != nil {
			log.Fatal(err)
		}
		defer d.PowerOff()
	}
	client, err := NewClient256(d)
	if err != nil {
		t.Fatalf("Could not initialize client: %v", err)
	}

	certifyKeyReq := CertifyKeyReq[SHA256Digest]{
		ContextHandle: [16]byte{0},
		Flags:         0,
		Label:         [32]byte{1, 2, 3, 4, 5},
		Format:        CertifyKeyX509,
	}

	// Get DPE leaf certificate from CertifyKey
	certifyKeyResp, err := client.CertifyKey(&certifyKeyReq)
	if err != nil {
		t.Fatalf("Could not certify key: %v", err)
	}

	// Get root and intermediate certificates to validate certificate chain of leaf cert
	getCertificateChainResp, err := client.GetCertificateChain()
	if err != nil {
		t.Fatalf("Could not get Certificate Chain: %v", err)
	}

	leafCertBytes := certifyKeyResp.Certificate
	certChainBytes := getCertificateChainResp.CertificateChain

	// Run X.509 linter on full certificate chain and file issues for errors
	leafCert := checkCertificateStructure(t, leafCertBytes)
	if leafCert == nil {
		t.Fatalf("Could not obtain leaf certificate from CertifyKey command.")
	}
	t.Logf("Leaf certificate is DER encoded")

	certChain := checkCertificateChain(t, certChainBytes)
	if certChain == nil || len(certChain) == 0 {
		t.Fatalf("Could not obtain certificate chain from GetCertificateChain command.")
	}
	t.Logf("Certificate chain is DER encoded")

	// Validate that all X.509 fields conform with the format defined in the DPE iRoT profile
	validateCertifyKeyFields(t, leafCert)

	// Validate that proper TcbInfo extensions are populated with expected measurements and values as defined in the DPE iRoT profile

	// Validate correct KeyUsage and BasicConstraints extensions for all DICE certificates

	// Ensure full certificate chain has valid signatures
	validateCertChain(t, certChain, leafCert)

	// TODO: When DeriveChild is implemented, call it here to add more TCIs and call CertifyKey again.
}

// Validate signature of certificates in certificate chain passed.
func validateSignature(t *testing.T, certchain []*x509.Certificate) {
	t.Helper()
	foundError := false
	for i := 0; i < len(certchain)-1; i++ {
		err := certchain[i].CheckSignatureFrom(certchain[i+1])
		if err != nil {
			t.Logf("Signature validation failed for certificate %s in chain with error %s", certchain[i].Subject.String(), err.Error())
			foundError = true
		} else {
			t.Logf("Signature validation passed %s", certchain[i].Subject.String())
		}

	}

	root := certchain[len(certchain)-1]
	//err := root.CheckSignatureFrom(root)
	err := root.CheckSignature(root.SignatureAlgorithm, root.RawTBSCertificate, root.Signature)
	if err != nil {
		t.Logf("Root certificate  %s Signature validation failed with error %s", root.Subject.String(), err.Error())
		foundError = true
	}
	t.Logf("Root certificate Signature validation passed %s\n", root.Subject.String())

	if foundError {
		// TODO: Fail the test when the certificate is expected to pass
		t.Logf("Found certificates with mismatching signature")
	}
}

// Build certificate chain and calls to validateSignature on each chain.
func validateCertChain(t *testing.T, certChain []*x509.Certificate, leafCert *x509.Certificate) {
	t.Helper()
	if leafCert != nil {
		// Remove unhandled critical extensions reported by x509 but defined in spec
		t.Log("Validating leaf certificate chain...")
		t.Log("Checking for unhandled critical certificate extensions unknown to DPE certificates profile spec...")
		removeTcgDiceCriticalExtensions(t, []*x509.Certificate{leafCert})

		// Build verify options
		opts := buildVerifyOptions(certChain)

		// Certificate chain validation for leaf
		chains, err := leafCert.Verify(opts)
		if err != nil {
			// TODO: Fail the test with Errorf here once we expect it to pass.
			t.Logf("Error in certificate chain %s: ", err.Error())
		}

		// Log certificate chains linked to leaf
		for _, chain := range chains {
			for i, cert := range chain {
				t.Logf("%d %s", i, (*cert).Subject)
			}

			// Validate signature of all certificate chains
			validateSignature(t, chain)
		}

		// This indicates that signature validation found no errors in the DPE leaf cert chain
		t.Logf("DPE leaf certificate chain validation is done")

	} else {
		// Remove unhandled critical extensions reported by x509 but defined in spec
		t.Log("Validating intermediate certificates chains...")
		t.Log("Checking for unhandled critical certificate extensions unknown to DPE certificates profile spec...")
		removeTcgDiceCriticalExtensions(t, certChain)

		// Build verify options
		opts := buildVerifyOptions(certChain)

		// Certificate chain validation for each intermediate certificate
		for _, cert := range certChain {
			chains, err := cert.Verify(opts)
			if err != nil {
				// TODO: Fail the test with Errorf here once we expect it to pass.
				t.Logf("Error in Certificate Chain of %s: %s", cert.Subject, err.Error())
			}

			// Log certificate chains linked to each cetificate in chain
			for _, chain := range chains {
				for i, cert := range chain {
					t.Logf("%d %s", i, (*cert).Subject)
				}
				// Validate signature of all certificate chains
				validateSignature(t, chain)
			}
		}

		// This indicates that signature validation found no errors each cert
		// chain of intermediate certificates
		t.Logf("Intermediate certificates chain validation is done")
	}
}

func buildVerifyOptions(certChain []*x509.Certificate) x509.VerifyOptions {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	for _, cert := range certChain {
		if cert.Subject.String() == cert.Issuer.String() {
			roots.AddCert(cert)
			continue
		} else {
			intermediates.AddCert(cert)
		}
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now().UTC(),
	}

	return opts
}

func extractFlagBit(pos int, flags uint32) bool {
	var mask uint32 = (1 << pos)
	return (flags & mask) > 0
}

func getKeyUsageNames(keyUsage x509.KeyUsage) []string {
	keyUsageNames := []string{}

	if keyUsage&x509.KeyUsageDigitalSignature == 1 {
		keyUsageNames = append(keyUsageNames, "DigitalSignature")
	}

	if keyUsage&x509.KeyUsageContentCommitment == 1 {
		keyUsageNames = append(keyUsageNames, "ContentCommitment")
	}

	if keyUsage&x509.KeyUsageKeyEncipherment == 1 {
		keyUsageNames = append(keyUsageNames, "KeyEncipherment")
	}

	if keyUsage&x509.KeyUsageDataEncipherment == 1 {
		keyUsageNames = append(keyUsageNames, "DataEncipherment")
	}

	if keyUsage&x509.KeyUsageKeyAgreement == 1 {
		keyUsageNames = append(keyUsageNames, "KeyAgreement")
	}

	if keyUsage&x509.KeyUsageCertSign == 1 {
		keyUsageNames = append(keyUsageNames, "CertSign")
	}

	if keyUsage&x509.KeyUsageCRLSign == 1 {
		keyUsageNames = append(keyUsageNames, "CRLSign")
	}

	if keyUsage&x509.KeyUsageEncipherOnly == 1 {
		keyUsageNames = append(keyUsageNames, "EncipherOnly")
	}

	if keyUsage&x509.KeyUsageDecipherOnly == 1 {
		keyUsageNames = append(keyUsageNames, "DecipherOnly")
	}

	return keyUsageNames
}
