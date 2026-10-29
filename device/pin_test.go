/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync/atomic"
	"testing"
	"time"
)

// bytesFor returns the bytes that make up rate bits per second over one
// pinSenderWindow.
func bytesFor(rate float64) int64 {
	return int64(rate / 8 * pinSenderWindow.Seconds())
}

func TestSenderPinJudge(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	j := newSenderPinJudge(t0)
	now := t0

	// window counts how many whole windows have been judged so far.
	window := func(bytes int64, want senderPinAction, what string) {
		t.Helper()
		j.add(bytes)
		now = now.Add(pinSenderWindow)
		if got, _ := j.judge(now); got != want {
			t.Fatalf("%s: got action %d, want %d", what, got, want)
		}
	}

	// A window that is still open changes nothing, and keeps its bytes.
	j.add(bytesFor(pinSenderRate))
	if got, rate := j.judge(now.Add(pinSenderWindow / 2)); got != senderPinKeep || rate != 0 {
		t.Fatalf("open window: got action %d rate %v, want keep and 0", got, rate)
	}
	j.add(bytesFor(pinSenderRate)) // closes below with 2x the bytes
	now = now.Add(pinSenderWindow)
	if got, rate := j.judge(now); got != senderPinDo || rate < pinSenderRate {
		t.Fatalf("first full window: got action %d rate %v, want pin and >= %d", got, rate, pinSenderRate)
	}
	// Until the caller confirms the pin, the judge keeps asking.
	window(bytesFor(pinSenderRate), senderPinDo, "pin not yet confirmed")
	j.setPinned(true)

	// While pinned, every window is a check, and a rate between the two
	// thresholds keeps the pin.
	window(bytesFor(pinSenderRate), senderPinCheck, "busy while pinned")
	window(bytesFor(unpinSenderRate), senderPinCheck, "between the thresholds")
	window(bytesFor(pinSenderRate), senderPinCheck, "busy again")

	// Quiet windows become an unpin only once unpinSenderAfter has passed,
	// and one busy window in between starts the quiet period over.
	quietWindows := int(unpinSenderAfter / pinSenderWindow)
	for i := 0; i < quietWindows-1; i++ {
		window(0, senderPinCheck, "quiet, not yet a minute")
	}
	window(bytesFor(pinSenderRate), senderPinCheck, "busy again before the minute")
	for i := 0; i < quietWindows; i++ {
		window(0, senderPinCheck, "quiet again, not yet a minute")
	}
	window(0, senderPinUndo, "quiet for a minute")

	// A failed unpin defers the next attempt by a minute.
	j.deferUnpin(now)
	for i := 0; i < quietWindows-1; i++ {
		window(0, senderPinCheck, "quiet after a failed unpin")
	}
	window(0, senderPinUndo, "a minute after the failed unpin")
	j.setPinned(false)

	// Unpinned and quiet: nothing to do.
	window(0, senderPinKeep, "unpinned and quiet")
	window(bytesFor(unpinSenderRate), senderPinKeep, "unpinned, below the pin rate")
}

// testCounter is a [Counter] for tests.
type testCounter struct{ atomic.Int64 }

func (c *testCounter) Add(n int64) { c.Int64.Add(n) }

// TestTwoDevicePingSenderPinning runs the ping test with sender pinning on,
// so that the pinning send loop and its shutdown run under the leak check.
// Test traffic stays far below pinSenderRate, so nothing is pinned, and the
// counters must agree on that.
func TestTwoDevicePingSenderPinning(t *testing.T) {
	goroutineLeakCheck(t)
	var pins, unpins, errs testCounter
	pair := genTestPair(t, true, WithSenderPinning(true), WithMetrics(Metrics{
		SenderPins:      &pins,
		SenderUnpins:    &unpins,
		SenderPinErrors: &errs,
	}))
	t.Run("ping 1.0.0.1", func(t *testing.T) {
		pair.Send(t, Ping, nil)
	})
	t.Run("ping 1.0.0.2", func(t *testing.T) {
		pair.Send(t, Pong, nil)
	})
	for i := range pair {
		pair[i].dev.Close()
	}
	if p, u, e := pins.Load(), unpins.Load(), errs.Load(); p != 0 || u != 0 || e != 0 {
		t.Fatalf("pins %d unpins %d errors %d, want 0 0 0 at test traffic rates", p, u, e)
	}
}
