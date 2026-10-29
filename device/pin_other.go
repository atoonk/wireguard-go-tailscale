//go:build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

// Sender pinning only exists on Linux, where the kernel picks a NIC transmit
// queue from the sending CPU. See pin.go.
const senderPinSupported = false

type senderPin struct{}

func (*senderPin) pin() (int, error)         { return 0, nil }
func (*senderPin) check() (bool, int, error) { return false, 0, nil }
func (*senderPin) unpin() error              { return nil }
