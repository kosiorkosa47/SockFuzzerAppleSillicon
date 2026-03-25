// Copyright 2024 ckosiorkosa47
// SPDX-License-Identifier: Apache-2.0
//
// Fork-based snapshot server implementation.
//
// Design: after the kernel is initialized, fork() creates a child for
// each iteration. The child inherits a clean copy-on-write snapshot
// of all kernel state. When the child exits (normally or via crash),
// the parent forks again for the next iteration.
//
// Limitations:
// - libFuzzer coverage counters are in the child's address space and
//   are lost when the child exits. This implementation is primarily
//   useful for crash reproduction and validation, not for coverage-
//   guided fuzzing. Full integration with libFuzzer requires shared
//   memory for coverage counters (future work).
// - Enabled via SOCKFUZZER_FORK_MODE=1 environment variable.

#include "fuzz/snapshot/fork_server.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static bool g_fork_mode = false;

bool fork_server_init(void) {
  const char *env = getenv("SOCKFUZZER_FORK_MODE");
  if (env && strcmp(env, "1") == 0) {
    g_fork_mode = true;
    fprintf(stderr, "[fork_server] Fork mode enabled — each iteration "
                    "runs in an isolated child process\n");
    return true;
  }
  return false;
}

bool fork_server_active(void) {
  return g_fork_mode;
}

int fork_server_run(fork_iteration_fn fn, const uint8_t *data, size_t size) {
  if (!g_fork_mode) {
    // Not in fork mode — run directly.
    return fn(data, size);
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("[fork_server] fork failed");
    // Fall back to direct execution.
    return fn(data, size);
  }

  if (pid == 0) {
    // Child: run the iteration and exit.
    int result = fn(data, size);
    _exit(result);
  }

  // Parent: wait for child.
  int status = 0;
  waitpid(pid, &status, 0);

  if (WIFSIGNALED(status)) {
    int sig = WTERMSIG(status);
    fprintf(stderr, "[fork_server] Child killed by signal %d (%s)\n",
            sig, strsignal(sig));
    return 128 + sig;
  }

  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
