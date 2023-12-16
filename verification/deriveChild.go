// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"testing"
)

func TestDeriveChild(d TestDPEInstance, c DPEClient, t *testing.T) {
	var resp *DeriveChildResp

	simulation := false
	handle := getInitialContextHandle(d, c, t, simulation)
	defer func() {
		c.DestroyContext(handle, DestroyDescendants)
	}()

	// Get digest size
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	digestLen := profile.GetDigestSize()

	// Child context handle returned will be the default context handle when MakeDefault flag is set
	if resp, err = c.DeriveChild(handle, make([]byte, digestLen), MakeDefault, 0, 0); err != nil {
		t.Errorf("[ERROR]: Error while creating child context handle: %s", err)
	}
	handle = &resp.NewContextHandle
	if resp.NewContextHandle != DefaultContextHandle {
		t.Fatalf("[FATAL]: Incorrect handle. Should return %v, but returned %v", DefaultContextHandle, *handle)
	}

	// When there is already a default handle, setting MakeDefault and RetainParent will cause error
	// because there cannot be two default handles in a locality
	if _, err = c.DeriveChild(handle, make([]byte, digestLen), MakeDefault|RetainParent, 0, 0); err == nil {
		t.Errorf("[ERROR]: Should return %q, but returned no error", StatusInvalidArgument)
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Errorf("[ERROR]: Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}

	// Retain parent should fail because parent handle is a default handle
	// and child handle will be a non-default handle.
	// Default and non-default handle cannot coexist in same locality.
	if _, err = c.DeriveChild(handle, make([]byte, digestLen), RetainParent, 0, 0); err == nil {
		t.Errorf("[ERROR]: Should return %q, but returned no error", StatusInvalidArgument)
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Errorf("[ERROR]: Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}

	// Child context handle should be a random handle when MakeDefault flag is NOT used
	if resp, err = c.DeriveChild(handle, make([]byte, digestLen), 0, 0, 0); err != nil {
		t.Errorf("[ERROR]: Error while creating child context handle: %s", err)
	}
	handle = &resp.NewContextHandle
	if resp.NewContextHandle == DefaultContextHandle {
		t.Fatalf("[FATAL]: Incorrect handle. Should return non-default handle, but returned %v", *handle)
	}
	if resp.ParentContextHandle != InvalidatedContextHandle {
		t.Errorf("[ERROR]: Incorrect handle. Should be invalidated when retain parent is NOT set, but returned %v", resp.ParentContextHandle)
	}

	// Now, there is no default handle, setting RetainParent flag should succeed
	if resp, err = c.DeriveChild(handle, make([]byte, digestLen), RetainParent, 0, 0); err != nil {
		t.Errorf("[ERROR]: Error while making child context handle as default handle: %s", err)
	}
	handle = &resp.NewContextHandle
	parentHandle := resp.ParentContextHandle

	if parentHandle == InvalidatedContextHandle {
		t.Errorf("[ERROR]: Incorrect handle. Should return retained handle, but returned invalidated handle %v", parentHandle)
	}
}

func TestChangeLocality(d TestDPEInstance, c DPEClient, t *testing.T) {
	var resp *DeriveChildResp
	simulation := false
	handle := getInitialContextHandle(d, c, t, simulation)
	// Clean up contexts
	defer func() {
		err := c.DestroyContext(handle, DestroyDescendants)
		if err != nil {
			t.Errorf("[ERROR]: Error while cleaning contexts, this may cause failure in subsequent tests: %s", err)
		}
	}()

	// Get digest size
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	if !d.HasLocalityControl() {
		t.Skip("WARNING: DPE profile does not have control over locality. Skipping this test...")
	}

	digestLen := profile.GetDigestSize()
	currentLocality := d.GetLocality()
	otherLocality := currentLocality + 1

	// Create child context in other locality
	if resp, err = c.DeriveChild(handle, make([]byte, digestLen), ChangeLocality, 0, otherLocality); err != nil {
		t.Fatalf("[ERROR]: Error while creating child context handle in other locality: %s", err)
	}
	handle = &resp.NewContextHandle

	// Revert to same locality from other locality
	prevLocality := currentLocality
	d.SetLocality(otherLocality)

	if resp, err = c.DeriveChild(handle, make([]byte, digestLen), ChangeLocality, 0, prevLocality); err != nil {
		t.Fatalf("[FATAL]: Error while creating child context handle in previous locality: %s", err)
	}
	handle = &resp.NewContextHandle
	d.SetLocality(prevLocality)
}

// Checks whether the DeriveChild input flags - InternalDiceInfo, InternalInputInfo are supported
// while creating child contexts when these features are supported in DPE profile.
func TestInternalInputFlags(d TestDPEInstance, c DPEClient, t *testing.T) {
	var resp *DeriveChildResp
	simulation := false
	handle := getInitialContextHandle(d, c, t, simulation)
	defer func() {
		c.DestroyContext(handle, DestroyDescendants)
	}()

	// Get digest size
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	digestLen := profile.GetDigestSize()
	// Internal input flags
	if d.GetSupport().InternalDice {
		if resp, err = c.DeriveChild(handle, make([]byte, digestLen), DeriveChildFlags(InternalInputDice), 0, 0); err != nil {
			t.Errorf("[ERROR]: Error while making child context handle as default handle: %s", err)
		}
		handle = &resp.NewContextHandle
	} else {
		t.Skip("[WARNING]: Profile has no support for \"InternalInputDice\" flag. Skipping the validation for this flag...")
	}

	if d.GetSupport().InternalInfo {
		if resp, err = c.DeriveChild(handle, make([]byte, digestLen), DeriveChildFlags(InternalInputInfo), 0, 0); err != nil {
			t.Errorf("[ERROR]: Error while making child context handle as default handle: %s", err)
		}
		handle = &resp.NewContextHandle
	} else {
		t.Skip("[WARNING]: Profile has no support for \"InternalInputInfo\" flag. Skipping the validation for this flag...")
	}
}

// Checks the privilege escalation of child
// When commands try to make use of features that are unsupported by child context, they fail.
func TestPrivilegesEscalation(d TestDPEInstance, c DPEClient, t *testing.T) {
	var err error
	simulation := false
	handle := getInitialContextHandle(d, c, t, simulation)

	// Get digest size
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	digestLen := profile.GetDigestSize()

	// Create a child TCI node with no special privileges
	resp, err := c.DeriveChild(handle,
		make([]byte, digestLen),
		DeriveChildFlags(0),
		0, 0)
	if err != nil {
		t.Fatalf("[FATAL]: Error encountered in getting child context: %v", err)
	}
	handle = &resp.NewContextHandle

	// Adding new privileges to child that parent does NOT possess will cause failure
	_, err = c.DeriveChild(handle,
		make([]byte, digestLen),
		DeriveChildFlags(InputAllowX509|InputAllowCA),
		0, 0)
	if err == nil {
		t.Errorf("[ERROR]: Should return %q, but returned no error", StatusInvalidArgument)
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Errorf("[ERROR]: Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}

	// Similarly, when commands like CertifyKey try to make use of features/flags that are unsupported
	// by child context, it will fail.
	if _, err = c.CertifyKey(handle, make([]byte, digestLen), CertifyKeyX509, CertifyAddIsCA); err == nil {
		t.Errorf("[ERROR]: Should return %q, but returned no error", StatusInvalidArgument)
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Errorf("[ERROR]: Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}
}

// Checks whether the number of derived contexts (TCI nodes) are limited by MAX_TCI_NODES attribute of the profile
func TestMaxTCIs(d TestDPEInstance, c DPEClient, t *testing.T) {
	var resp *DeriveChildResp

	simulation := false
	handle := getInitialContextHandle(d, c, t, simulation)
	defer func() { c.DestroyContext(handle, DestroyDescendants) }()

	// Get digest size
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestSize := profile.GetDigestSize()

	// Get Max TCI count
	maxTciCount := int(d.GetMaxTciNodes())
	allowedTciCount := maxTciCount - 1 // since, a TCI node is already auto-initialized
	for i := 0; i < allowedTciCount; i++ {
		resp, err = c.DeriveChild(handle, make([]byte, digestSize), 0, 0, 0)
		if err != nil {
			t.Fatalf("[FATAL]: Error encountered in executing derive child: %v", err)
		}
		handle = &resp.NewContextHandle
	}

	// Exceed the Max TCI node count limit
	_, err = c.DeriveChild(handle, make([]byte, digestSize), 0, 0, 0)
	if err == nil {
		t.Fatalf("[FATAL]: Should return %q, but returned no error", StatusMaxTCIs)
	} else if !errors.Is(err, StatusMaxTCIs) {
		t.Fatalf("[FATAL]: Incorrect error type. Should return %q, but returned %q", StatusMaxTCIs, err)
	}
}

func TestDeriveChildSimulation(d TestDPEInstance, c DPEClient, t *testing.T) {
	var resp *DeriveChildResp

	simulation := true
	handle := getInitialContextHandle(d, c, t, simulation)
	defer func() {
		c.DestroyContext(handle, DestroyDescendants)
	}()

	// Get digest size
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	digestLen := profile.GetDigestSize()
	locality := d.GetLocality()

	// MakeDefault should fail because parent handle is a non-default handle
	// and child handle will be a default handle.
	// Default and non-default handle cannot coexist in same locality.
	if _, err = c.DeriveChild(handle, make([]byte, digestLen), MakeDefault, 0, 0); err == nil {
		t.Errorf("[ERROR]: Should return %q, but returned no error", StatusInvalidArgument)
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Errorf("[ERROR]: Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}

	// Make default child context in other locality
	childCtx, err := c.DeriveChild(handle,
		make([]byte, digestLen),
		DeriveChildFlags(ChangeLocality|RetainParent|MakeDefault),
		0,
		locality+1) // Switch locality to derive child context from Simulation context

	if err != nil {
		t.Fatalf("[FATAL]: Error while creating child handle: %s", err)
	}

	handle = &childCtx.NewContextHandle
	parentHandle := &childCtx.ParentContextHandle

	// Clean up parent context
	defer func() {
		err := c.DestroyContext(parentHandle, DestroyDescendants)
		if err != nil {
			t.Errorf("[ERROR]: Error while cleaning contexts, this may cause failure in subsequent tests: %s", err)
		}
	}()

	d.SetLocality(locality + 1)

	defer func() {
		// Clean up contexts after test
		err := c.DestroyContext(handle, DestroyDescendants)
		if err != nil {
			t.Errorf("[ERROR]: Error while cleaning up derived context, this may cause failure in subsequent tests: %s", err)
		}
		// Revert locality for other tests
		d.SetLocality(locality)
	}()

	// Retain parent should fail because parent handle is a default handle
	// and child handle will be a non-default handle.
	// Default and non-default handle cannot coexist in same locality.
	if _, err = c.DeriveChild(handle, make([]byte, digestLen), RetainParent, 0, 0); err == nil {
		t.Errorf("[ERROR]: Should return %q, but returned no error", StatusInvalidArgument)
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Errorf("[ERROR]: Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}

	// Setting RetainParent flag should not invalidate the parent handle
	if resp, err = c.DeriveChild(handle, make([]byte, digestLen), RetainParent, 0, 0); err != nil {
		t.Fatalf("[FATAL]: Error while making child context and retaining parent handle %s", err)
	}
	handle = &resp.NewContextHandle

	if resp.ParentContextHandle == InvalidatedContextHandle {
		t.Errorf("[ERROR]: Incorrect handle. Should return retained handle, but returned invalidated handle %v", parentHandle)
	}
}
