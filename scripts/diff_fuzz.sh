#!/bin/bash
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# Differential fuzzing between two SockFuzzer builds.
# Runs the same corpus through both binaries and compares behavior.
#
# Usage: ./scripts/diff_fuzz.sh <fuzzer_a> <fuzzer_b> <corpus_dir>
#
# Example:
#   # Build two versions with different XNU sources
#   cd build_old && cmake .. && make net_fuzzer && cd ..
#   cd build_new && cmake .. && make net_fuzzer && cd ..
#   ./scripts/diff_fuzz.sh build_old/net_fuzzer build_new/net_fuzzer corpus/

set -e

FUZZER_A="${1:?Usage: $0 <fuzzer_a> <fuzzer_b> <corpus_dir>}"
FUZZER_B="${2:?Usage: $0 <fuzzer_a> <fuzzer_b> <corpus_dir>}"
CORPUS="${3:?Usage: $0 <fuzzer_a> <fuzzer_b> <corpus_dir>}"
RESULTS_DIR="diff_results_$(date +%Y%m%d_%H%M%S)"

for f in "$FUZZER_A" "$FUZZER_B"; do
  if [ ! -x "$f" ]; then
    echo "Error: $f not found or not executable"
    exit 1
  fi
done

if [ ! -d "$CORPUS" ]; then
  echo "Error: corpus directory $CORPUS not found"
  exit 1
fi

mkdir -p "$RESULTS_DIR"

INPUTS=$(find "$CORPUS" -type f | sort)
TOTAL=$(echo "$INPUTS" | wc -l | tr -d ' ')
DIFFS=0
CRASHES_A=0
CRASHES_B=0

echo "=== Differential Fuzzing ==="
echo "Fuzzer A: $FUZZER_A"
echo "Fuzzer B: $FUZZER_B"
echo "Corpus:   $TOTAL inputs"
echo "Output:   $RESULTS_DIR/"
echo ""

for input in $INPUTS; do
  name=$(basename "$input")

  # Run both fuzzers on the same input
  ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=1 \
    timeout 5 "$FUZZER_A" "$input" > /dev/null 2> "$RESULTS_DIR/a_${name}.stderr" || true
  EXIT_A=$?

  ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=1 \
    timeout 5 "$FUZZER_B" "$input" > /dev/null 2> "$RESULTS_DIR/b_${name}.stderr" || true
  EXIT_B=$?

  if [ "$EXIT_A" -ne "$EXIT_B" ]; then
    DIFFS=$((DIFFS + 1))
    echo "DIFF: $name — A=$EXIT_A B=$EXIT_B"

    if [ "$EXIT_A" -ne 0 ]; then CRASHES_A=$((CRASHES_A + 1)); fi
    if [ "$EXIT_B" -ne 0 ]; then CRASHES_B=$((CRASHES_B + 1)); fi

    # Save the differing input
    cp "$input" "$RESULTS_DIR/diff_${name}"
  fi
done

echo ""
echo "=== Results ==="
echo "  Total inputs:   $TOTAL"
echo "  Behavioral diffs: $DIFFS"
echo "  Crashes in A only: $CRASHES_A"
echo "  Crashes in B only: $CRASHES_B"
echo "  Saved to: $RESULTS_DIR/"

if [ "$DIFFS" -gt 0 ]; then
  echo ""
  echo "Differences found — investigate diff_* files in $RESULTS_DIR/"
fi
