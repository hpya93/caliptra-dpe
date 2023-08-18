// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"log"
	"testing"
)

// This file is used to test the initialize context command by using a simulator

func TestInitializeContext(t *testing.T) {
	var socketFeatures []TestDPEInstance
	if *isEmulator {
		//Added dummy support for emulator. Once the emulator is implemented, will add the actual enabled feature
		socketFeatures = []TestDPEInstance{
			&DpeInstance{exe_path: *socket_exe, supports: Support{AutoInit: true}},
		}
	} else {
		socketFeatures = []TestDPEInstance{
			// No extra options.
			&DpeInstance{exe_path: *socket_exe},
			// Supports simulation.
			&DpeInstance{exe_path: *socket_exe, supports: Support{Simulation: true}},
		}
	}

	for _, s := range socketFeatures {
		for _, l := range s.GetSupportedLocalities() {
			s.SetLocality(l)
			testInitContext(s, t)
		}
	}
}

func testInitContext(d TestDPEInstance, t *testing.T) {
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

	// Try to create the default context if isn't done automatically.
	if !d.GetSupport().AutoInit {
		initCtxResp, err := client.InitializeContext(NewInitCtxIsDefault())
		if err != nil {
			t.Fatalf("Failed to initialize default context: %v", err)
		}
		if initCtxResp.Handle != [16]byte{0} {
			t.Fatal("Incorrect default context handle.")
		}
		defer client.DestroyContext(NewDestroyCtx(initCtxResp.Handle, false))
	}

	// Try to initialize another default context.
	_, err = client.InitializeContext(NewInitCtxIsDefault())
	if err == nil {
		t.Fatal("The instance should return an error when trying to initialize another default context.")
	} else if !errors.Is(err, StatusArgumentNotSupported) {
		t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusArgumentNotSupported, err)
	}

	// Try to initialize a context that is neither default or simulation.
	_, err = client.InitializeContext(&InitCtxCmd{})
	if err == nil {
		t.Fatal("The instance should return an error when not default or simulation.")
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}

	if !d.GetSupport().Simulation {
		// Try to initialize a simulation context when they aren't supported.
		_, err = client.InitializeContext(NewInitCtxIsSimulation())
		if err == nil {
			t.Fatal("The instance should return an error when trying to initialize another default context.")
		} else if !errors.Is(err, StatusArgumentNotSupported) {
			t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusArgumentNotSupported, err)
		}
	} else {
		getProfileRsp, err := client.GetProfile()
		if err != nil {
			t.Fatalf("Failed to get profile: %v", err)
		}

		// Try to get the correct error for overflowing the contexts. Fill up the
		// rest of the contexts (-1 for default).
		for i := uint32(0); i < getProfileRsp.MaxTciNodes-1; i++ {
			initCtxResp, err := client.InitializeContext(NewInitCtxIsSimulation())
			if err != nil {
				t.Fatal("The instance should be able to create a simulation context.")
			}
			// Could prove difficult to prove it is a cryptographically secure random.
			if initCtxResp.Handle == [16]byte{0} {
				t.Fatal("Incorrect simulation context handle.")
			}
			defer client.DestroyContext(NewDestroyCtx(initCtxResp.Handle, false))
		}

		// Now try to make one more than the max.
		_, err = client.InitializeContext(NewInitCtxIsSimulation())
		if err == nil {
			t.Fatal("Failed to report an error for too many contexts.")
		} else if !errors.Is(err, StatusMaxTCIs) {
			t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusMaxTCIs, err)
		}
	}
}
