#!/bin/bash
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# Generate seed corpus by running the fuzzer briefly.
# Seeds bootstrap coverage so the fuzzer doesn't start from scratch.
#
# Usage: ./scripts/generate_seeds.sh [fuzzer_binary] [duration_seconds]

set -e

FUZZER="${1:-build/net_fuzzer}"
DURATION="${2:-30}"
SEED_DIR="corpus/seeds"
TEMP_CORPUS=$(mktemp -d)

if [ ! -x "$FUZZER" ]; then
  echo "Error: fuzzer binary not found: $FUZZER"
  echo "Build first: mkdir build && cd build && cmake .. && make -j"
  exit 1
fi

echo "Generating seeds for $DURATION seconds..."
mkdir -p "$SEED_DIR"

ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=0 \
  "$FUZZER" "$TEMP_CORPUS" \
  -dict=net_fuzzer.dict \
  -max_total_time="$DURATION" \
  -max_len=4096 \
  2>&1 | tail -5

# Merge into seeds (deduplicate by coverage)
echo "Merging into $SEED_DIR..."
ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=0 \
  "$FUZZER" -merge=1 "$SEED_DIR" "$TEMP_CORPUS" 2>&1 | tail -3

rm -rf "$TEMP_CORPUS"

COUNT=$(find "$SEED_DIR" -type f -not -name "README*" | wc -l)
echo "Done: $COUNT seeds in $SEED_DIR"
