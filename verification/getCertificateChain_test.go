// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"testing"

	zx509 "github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
)

// This file is used to test the Get Certificate Chain command by using a simulator/emulator

func TestGetCertificateChain(t *testing.T) {
	support_needed := []string{"AutoInit", "X509"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetCertificateChain command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}
	testGetCertificateChain(instance, t)
}

func TestGetCertificateChain_SimulationMode(t *testing.T) {

	support_needed := []string{"AutoInit", "Simulation", "X509"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetCertificateChain_SimulationMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}
	testGetCertificateChain(instance, t)
}

func testGetCertificateChain(d TestDPEInstance, t *testing.T) {
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

	getCertificateChainResp, err := client.GetCertificateChain()
	if err != nil {
		t.Fatalf("Could not get Certificate Chain: %v", err)
	}

	checkCertificateChain(t, getCertificateChainResp.CertificateChain)
}

func checkCertificateChain(t *testing.T, certData []byte) []*x509.Certificate {
	t.Helper()
	failed := false

	var x509Certs []*x509.Certificate
	var err error

	// Check whether certificate chain is DER encoded.
	if x509Certs, err = x509.ParseCertificates(certData); err != nil {
		t.Fatalf("Could not parse certificate using crypto/x509: %v", err)
	}

	// Parse the cert with zcrypto so we can lint it.
	certs, err := zx509.ParseCertificates(certData)
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

	for _, cert := range certs {
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
				Bytes: certData,
			})))
			t.Logf("Offending certificate (DER):\n%x", certData)
		}
	}

	validateCertChain(t, x509Certs, nil)
	return x509Certs
}
