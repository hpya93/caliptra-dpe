// Licensed under the Apache-2.0 license

package verification

import (
	"flag"
	"os"
	"testing"
)

var socket_exe *string
var isEmulator *bool

// This will be called before running tests, and it assigns the socket path based on command line flag.
func TestMain(m *testing.M) {
	isEmulator = flag.Bool("emulator", false, "socket type - emulator")
	flag.Parse()
	if !*isEmulator {
		socket_exe = flag.String("sim", "../simulator/target/debug/simulator", "path to simulator executable")
	} else {
		socket_exe = flag.String("emu", "../simulator/target/debug/emulator", "path to emulator executable")
	}

	exitVal := m.Run()
	os.Exit(exitVal)
}

// An extension to the main DPE transport interface with test hooks.
type TestDPEInstance interface {
	Transport
	// If power control is unavailable for the given device, return false from
	// HasPowerControl and return an error from PowerOn and PowerOff. For devices
	// that don't support power control but do have reset capability, return true
	// from HasPowerControl leave PowerOn empty and execute the reset in PowerOff.
	HasPowerControl() bool
	// If supported, turns on the device or starts the emulator/simulator.
	PowerOn() error
	// If supported, turns of the device, stops the emulator/simulator, or resets.
	PowerOff() error
	// The Transport implementations are not expected to be able to set the values
	// it supports, but this function is used by tests to know how to test the DPE
	// instance.
	GetSupport() *Support
	// Returns the profile the transport supports.
	GetProfile() Profile
	// Returns a slice of all the localities the instance supports.
	GetSupportedLocalities() []uint32
	// Sets the current locality.
	SetLocality(locality uint32)
	// Gets the current locality.
	GetLocality() uint32
	// Returns the Maximum number of the TCIs instance can have.
	GetMaxTciNodes() uint32
	// Returns the major version of the profile the instance implements.
	GetProfileMajorVersion() uint16
	// Returns the minor version of the profile the instance implements.
	GetProfileMinorVersion() uint16
	// Returns the Vendor ID of the profile.
	GetProfileVendorId() uint32
	// Returns the vendor's product SKU.
	GetProfileVendorSku() uint32
}
