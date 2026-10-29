/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import "time"

// Sender pinning, enabled with [WithSenderPinning].
//
// Each peer's sequential sender hands its batches to the kernel from
// whatever CPU the Go scheduler put it on. On Linux with a multi-queue NIC
// and XPS, which most drivers set up by default, the kernel picks the
// transmit queue from the sending CPU when the socket has no queue stored
// on it, and an unconnected UDP socket never has. So one peer's packets are
// spread over every transmit queue, the NIC drains those queues
// independently, the packets reach the wire out of order, and TCP inside the
// tunnel treats the reordering as loss. A single flow then stalls at about
// half of a 10G link.
//
// Pinning the sender's thread to one CPU keeps all of its sends on one
// queue. It is done only while the peer is busy, because a pinned goroutine
// holds an OS thread for itself, frozen on one CPU: a fair price for a peer
// moving gigabits and a silly one for a peer that was busy once an hour
// ago. The CPU chosen is the one the goroutine is on when it qualifies,
// which the scheduler just picked because it had room. While pinned, the
// sender checks every window that its affinity is still what it set, since
// the kernel resets a thread's affinity when the cpuset it runs in changes;
// if so it pins again where it is. Below a low rate for a minute it unpins
// and hands the thread back.

const (
	pinSenderWindow  = 3 * time.Second // how often the rate is judged
	pinSenderRate    = 10_000_000      // bits per second over a window: pin
	unpinSenderRate  = 2_500_000       // below this for unpinSenderAfter: unpin
	unpinSenderAfter = 60 * time.Second
)

// A senderPinAction is what a sequential sender should do to its pin after
// a window has been judged.
type senderPinAction uint8

const (
	senderPinKeep  senderPinAction = iota // nothing to do
	senderPinDo                           // pin: the rate crossed pinSenderRate while unpinned
	senderPinCheck                        // pinned: verify that the affinity still holds
	senderPinUndo                         // unpin: below unpinSenderRate for unpinSenderAfter
)

// senderPinJudge decides from a sequential sender's send rate whether its
// thread should be pinned. It is used by one goroutine only and knows
// nothing about threads: the caller reports what it sent and what it did.
type senderPinJudge struct {
	pinned      bool
	bytes       int64     // sent since windowStart
	windowStart time.Time // start of the window being measured
	quietSince  time.Time // first window below unpinSenderRate while pinned, or zero
}

func newSenderPinJudge(now time.Time) senderPinJudge {
	return senderPinJudge{windowStart: now}
}

// add records n sent bytes.
func (j *senderPinJudge) add(n int64) {
	j.bytes += n
}

// judge closes the current window if pinSenderWindow has elapsed and says
// what to do. It also reports the window's rate in bits per second, which is
// 0 when the window is still open.
func (j *senderPinJudge) judge(now time.Time) (senderPinAction, float64) {
	elapsed := now.Sub(j.windowStart)
	if elapsed < pinSenderWindow {
		return senderPinKeep, 0
	}
	rate := float64(j.bytes) * 8 / elapsed.Seconds()
	j.bytes, j.windowStart = 0, now
	if !j.pinned {
		if rate >= pinSenderRate {
			return senderPinDo, rate
		}
		return senderPinKeep, rate
	}
	switch {
	case rate >= unpinSenderRate:
		j.quietSince = time.Time{}
	case j.quietSince.IsZero():
		j.quietSince = now
	case now.Sub(j.quietSince) >= unpinSenderAfter:
		return senderPinUndo, rate
	}
	return senderPinCheck, rate
}

// setPinned records that the caller pinned or unpinned the thread.
func (j *senderPinJudge) setPinned(pinned bool) {
	j.pinned = pinned
	j.quietSince = time.Time{}
}

// deferUnpin is called when an unpin failed: the quiet period starts over,
// so the next attempt is a minute away rather than a window.
func (j *senderPinJudge) deferUnpin(now time.Time) {
	j.quietSince = now
}
