// Copyright 2024 ckosiorkosa47
// SPDX-License-Identifier: Apache-2.0

#include "fuzz/concurrent/concurrent_harness.h"

#include <cstdio>

// Placeholder implementation — runs streams sequentially.
// Full coroutine-based interleaving requires linking the
// CoroutineExecutor and scheduling switches at syscall boundaries.
//
// To enable real concurrent fuzzing:
// 1. Link against CoroutineExecutor
// 2. Create coroutine per stream
// 3. Insert yield points before/after each syscall wrapper call
// 4. Use scheduler_decisions to determine switch order

bool run_concurrent(
    std::function<void()> stream_a,
    std::function<void()> stream_b,
    const std::vector<bool> &scheduler_decisions) {

  // Sequential execution for now — safe, deterministic baseline.
  // The scheduler_decisions vector will drive interleaving once
  // coroutine integration is complete.
  (void)scheduler_decisions;

  stream_a();
  stream_b();

  return true;
}
