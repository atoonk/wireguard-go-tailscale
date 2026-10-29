//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

const senderPinSupported = true

// senderPin holds one sequential sender's thread pin. Only its goroutine
// uses it. See pin.go.
type senderPin struct {
	cpu  int
	want unix.CPUSet // the single-CPU affinity applied while pinned
	prev unix.CPUSet // the affinity before pinning, restored by unpin
}

// pin locks the calling goroutine to its OS thread and that thread to the
// CPU it is running on, and reports the CPU. On error nothing stays locked
// or pinned.
func (p *senderPin) pin() (int, error) {
	runtime.LockOSThread()
	var prev unix.CPUSet
	if err := unix.SchedGetaffinity(0, &prev); err != nil {
		runtime.UnlockOSThread()
		return 0, err
	}
	cpu, err := getcpu()
	if err != nil {
		runtime.UnlockOSThread()
		return 0, err
	}
	var want unix.CPUSet
	want.Set(cpu)
	if err := unix.SchedSetaffinity(0, &want); err != nil {
		runtime.UnlockOSThread()
		return 0, err
	}
	p.cpu, p.want, p.prev = cpu, want, prev
	return cpu, nil
}

// check verifies that the thread's affinity is still the one pin applied.
// If it is not, the kernel reset it (the cpuset the process runs in changed)
// or an administrator moved the thread; either way check pins again to the
// CPU the thread is on now and reports that it did. The affinity it found
// becomes the one unpin restores, since the old one may no longer be
// allowed.
func (p *senderPin) check() (repinned bool, cpu int, err error) {
	var cur unix.CPUSet
	if err := unix.SchedGetaffinity(0, &cur); err != nil {
		return false, p.cpu, err
	}
	if cur == p.want {
		return false, p.cpu, nil
	}
	cpu, err = getcpu()
	if err != nil {
		return false, p.cpu, err
	}
	var want unix.CPUSet
	want.Set(cpu)
	if err := unix.SchedSetaffinity(0, &want); err != nil {
		return false, p.cpu, err
	}
	p.cpu, p.want, p.prev = cpu, want, cur
	return true, cpu, nil
}

// unpin restores the thread's affinity and lets the goroutine move again.
// The affinity must be restored before the thread goes back to Go's pool,
// or an unrelated goroutine would inherit the pin; so if restoring it fails
// the thread stays locked, and Go retires it with the goroutine.
func (p *senderPin) unpin() error {
	if err := unix.SchedSetaffinity(0, &p.prev); err != nil {
		return err
	}
	runtime.UnlockOSThread()
	return nil
}

// getcpu returns the CPU the calling thread is running on.
func getcpu() (int, error) {
	var cpu uint32
	if _, _, e := unix.RawSyscall(unix.SYS_GETCPU, uintptr(unsafe.Pointer(&cpu)), 0, 0); e != 0 {
		return 0, e
	}
	return int(cpu), nil
}
