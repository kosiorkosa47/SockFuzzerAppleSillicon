// Copyright 2024 ckosiorkosa47
// SPDX-License-Identifier: Apache-2.0
//
// Concurrent syscall fuzzing harness.
// Uses the CoroutineExecutor to interleave two command streams,
// enabling detection of race conditions in XNU networking code.
//
// Integration with main fuzzer:
//   When a Session contains commands tagged for concurrent execution,
//   the harness splits them into two streams and runs them via
//   coroutines with fuzzed scheduling points.

#ifndef CONCURRENT_HARNESS_H_
#define CONCURRENT_HARNESS_H_

#include <functional>
#include <vector>

// Run two command sequences concurrently using coroutines.
// scheduler_decisions controls when to switch between streams.
// Returns true if both streams completed without assertion failure.
bool run_concurrent(
    std::function<void()> stream_a,
    std::function<void()> stream_b,
    const std::vector<bool> &scheduler_decisions);

#endif  // CONCURRENT_HARNESS_H_
