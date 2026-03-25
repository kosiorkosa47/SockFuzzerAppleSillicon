// Copyright 2024 ckosiorkosa47
// SPDX-License-Identifier: Apache-2.0
//
// Fork-based snapshot server for perfect state isolation between
// fuzzer iterations. Each iteration runs in a forked child process
// with copy-on-write memory, eliminating state leak bugs.

#ifndef FORK_SERVER_H_
#define FORK_SERVER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize the fork server after kernel network init.
// Call this once, after initialize_network() and init_proc().
// Returns true if fork server is available.
bool fork_server_init(void);

// Run a single fuzzer iteration in a forked child.
// Returns the child's exit status (0 = clean, nonzero = crash).
// The callback receives the input data and runs the fuzzer logic.
typedef int (*fork_iteration_fn)(const uint8_t *data, size_t size);
int fork_server_run(fork_iteration_fn fn, const uint8_t *data, size_t size);

// Check if fork server mode is active.
bool fork_server_active(void);

#ifdef __cplusplus
}
#endif

#endif  // FORK_SERVER_H_
