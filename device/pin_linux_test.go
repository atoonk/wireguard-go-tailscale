//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// affinityOrSkip returns the calling thread's affinity, skipping the test
// where pinning cannot be exercised: one CPU, or a sandbox that refuses
// sched_setaffinity.
func affinityOrSkip(t *testing.T) unix.CPUSet {
	t.Helper()
	if runtime.NumCPU() < 2 {
		t.Skip("needs at least two CPUs")
	}
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		t.Skipf("sched_getaffinity: %v", err)
	}
	if err := unix.SchedSetaffinity(0, &set); err != nil && (errors.Is(err, unix.EPERM) || errors.Is(err, unix.EINVAL)) {
		t.Skipf("sched_setaffinity: %v", err)
	}
	return set
}

func TestSenderPinRestoresAffinity(t *testing.T) {
	runtime.LockOSThread() // so the affinity we read and restore is this thread's
	defer runtime.UnlockOSThread()
	before := affinityOrSkip(t)

	var p senderPin
	cpu, err := p.pin()
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	var cur unix.CPUSet
	if err := unix.SchedGetaffinity(0, &cur); err != nil {
		t.Fatal(err)
	}
	if cur.Count() != 1 || !cur.IsSet(cpu) {
		t.Fatalf("after pin: affinity has %d CPUs, CPU %d set: %v", cur.Count(), cpu, cur.IsSet(cpu))
	}
	if err := p.unpin(); err != nil {
		t.Fatalf("unpin: %v", err)
	}
	if err := unix.SchedGetaffinity(0, &cur); err != nil {
		t.Fatal(err)
	}
	if cur != before {
		t.Fatalf("after unpin: affinity %v, want the one before pinning %v", cur, before)
	}
}

func TestSenderPinCheckRepins(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before := affinityOrSkip(t)

	var p senderPin
	if _, err := p.pin(); err != nil {
		t.Fatalf("pin: %v", err)
	}

	if repinned, _, err := p.check(); err != nil || repinned {
		t.Fatalf("check right after pin: repinned %v err %v, want false and nil", repinned, err)
	}

	// Pretend the kernel reset the affinity because the cpuset changed.
	if err := unix.SchedSetaffinity(0, &before); err != nil {
		t.Fatal(err)
	}
	repinned, cpu, err := p.check()
	if err != nil {
		t.Fatalf("check after reset: %v", err)
	}
	if !repinned {
		t.Fatal("check after reset: not repinned")
	}
	var cur unix.CPUSet
	if err := unix.SchedGetaffinity(0, &cur); err != nil {
		t.Fatal(err)
	}
	if cur.Count() != 1 || !cur.IsSet(cpu) {
		t.Fatalf("after repin: affinity has %d CPUs, CPU %d set: %v", cur.Count(), cpu, cur.IsSet(cpu))
	}
	if repinned, _, err := p.check(); err != nil || repinned {
		t.Fatalf("second check: repinned %v err %v, want false and nil", repinned, err)
	}

	// unpin restores the affinity found at the reset, not the original one.
	if err := p.unpin(); err != nil {
		t.Fatalf("unpin: %v", err)
	}
	if err := unix.SchedGetaffinity(0, &cur); err != nil {
		t.Fatal(err)
	}
	if cur != before {
		t.Fatalf("after unpin: affinity %v, want %v", cur, before)
	}
}
