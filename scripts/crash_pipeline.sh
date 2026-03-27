#!/bin/bash
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# Automated crash-to-report pipeline (#88)
#
# Takes a raw crash artifact and produces:
# 1. Minimized reproducer
# 2. ASAN triage report (bug class, stack trace)
# 3. Standalone C PoC
# 4. Markdown report draft for Apple Security Bounty
#
# Usage: ./scripts/crash_pipeline.sh <crash_file> [fuzzer_binary]

set -e

CRASH_FILE="${1:?Usage: $0 <crash_file> [fuzzer_binary]}"
FUZZER="${2:-build/net_fuzzer}"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_DIR="reports/$(date +%Y%m%d_%H%M%S)_$(basename "$CRASH_FILE" | cut -c1-12)"

if [ ! -f "$CRASH_FILE" ]; then
  echo "Error: crash file not found: $CRASH_FILE"
  exit 1
fi

if [ ! -x "$FUZZER" ]; then
  echo "Error: fuzzer not found: $FUZZER"
  exit 1
fi

mkdir -p "$REPORT_DIR"
echo "=== Crash Pipeline ==="
echo "Input:  $CRASH_FILE ($(wc -c < "$CRASH_FILE" | tr -d ' ') bytes)"
echo "Output: $REPORT_DIR/"
echo ""

# --- Stage 1: Minimize ---
echo "[1/4] Minimizing crash..."
MINIMIZED="$REPORT_DIR/minimized.bin"
set +e
ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=1 \
  "$FUZZER" -minimize_crash=1 \
  -exact_artifact_path="$MINIMIZED" \
  -max_total_time=60 \
  "$CRASH_FILE" 2>/dev/null
set -e

if [ ! -f "$MINIMIZED" ]; then
  cp "$CRASH_FILE" "$MINIMIZED"
  echo "  Minimization failed — using original"
fi
ORIG_SIZE=$(wc -c < "$CRASH_FILE" | tr -d ' ')
MIN_SIZE=$(wc -c < "$MINIMIZED" | tr -d ' ')
echo "  Original: $ORIG_SIZE bytes → Minimized: $MIN_SIZE bytes"

# --- Stage 2: Triage ---
echo "[2/4] Triaging crash (ASAN analysis)..."
TRIAGE="$REPORT_DIR/triage.txt"
set +e
ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=1:print_stats=1 \
  "$FUZZER" "$MINIMIZED" > "$TRIAGE" 2>&1
CRASH_EXIT=$?
set -e

# Extract bug class
BUG_CLASS="unknown"
if grep -q "heap-buffer-overflow" "$TRIAGE"; then BUG_CLASS="heap-buffer-overflow"; fi
if grep -q "heap-use-after-free" "$TRIAGE"; then BUG_CLASS="use-after-free"; fi
if grep -q "stack-buffer-overflow" "$TRIAGE"; then BUG_CLASS="stack-buffer-overflow"; fi
if grep -q "global-buffer-overflow" "$TRIAGE"; then BUG_CLASS="global-buffer-overflow"; fi
if grep -q "null-dereference\|SEGV.*address 0x0" "$TRIAGE"; then BUG_CLASS="null-pointer-dereference"; fi
if grep -q "ASSERT:" "$TRIAGE"; then BUG_CLASS="kernel-assertion-failure"; fi
if grep -q "KERNEL PANIC" "$TRIAGE"; then BUG_CLASS="kernel-panic"; fi

# Extract crashing function
CRASH_FUNC=$(grep "^    #0" "$TRIAGE" | head -1 | sed 's/.*in //' | cut -d' ' -f1 || echo "unknown")
CRASH_FILE_LOC=$(grep "^    #0" "$TRIAGE" | head -1 | grep -o '[^ ]*\.c:[0-9]*' || echo "unknown")

echo "  Bug class: $BUG_CLASS"
echo "  Function:  $CRASH_FUNC"
echo "  Location:  $CRASH_FILE_LOC"
echo "  Exit code: $CRASH_EXIT"

# --- Stage 3: PoC Generation ---
echo "[3/4] Generating PoC..."
POC="$REPORT_DIR/poc.c"
python3 "$SCRIPTS_DIR/poc_generator.py" "$MINIMIZED" "$POC" 2>/dev/null || \
  echo "// PoC generation requires protobuf Python bindings" > "$POC"
echo "  Generated: $POC"

# --- Stage 4: Report Draft ---
echo "[4/4] Generating Apple Security Bounty report..."
REPORT="$REPORT_DIR/report.md"
cat > "$REPORT" <<REPORTEOF
# Apple Security Bounty Report

## Bug Summary

| Field | Value |
|---|---|
| **Component** | XNU Kernel — Network Stack |
| **Bug Class** | $BUG_CLASS |
| **Crashing Function** | \`$CRASH_FUNC\` |
| **Source Location** | \`$CRASH_FILE_LOC\` |
| **Severity** | HIGH — Kernel code execution potential |
| **Affected Versions** | macOS / iOS (XNU-based) |

## Description

A $BUG_CLASS vulnerability was found in the XNU kernel network stack
using structure-aware fuzzing with SockFuzzer. The crash occurs in
\`$CRASH_FUNC\` at \`$CRASH_FILE_LOC\`.

## Impact

This vulnerability could potentially allow:
- Kernel code execution from an unprivileged process
- Denial of service (kernel panic)
- Information disclosure from kernel memory

## Reproduction Steps

1. Build the fuzzer:
   \`\`\`bash
   git clone --recursive <repo_url>
   mkdir build && cd build
   cmake .. -DCMAKE_C_COMPILER=\$(brew --prefix llvm)/bin/clang \\
            -DCMAKE_CXX_COMPILER=\$(brew --prefix llvm)/bin/clang++
   make -j
   \`\`\`

2. Reproduce the crash:
   \`\`\`bash
   ASAN_OPTIONS=detect_container_overflow=0:halt_on_error=1 \\
     ./net_fuzzer minimized.bin
   \`\`\`

3. Compile and run the standalone PoC:
   \`\`\`bash
   cc -o poc poc.c
   ./poc
   \`\`\`

## ASAN Report

\`\`\`
$(head -50 "$TRIAGE")
\`\`\`

## Stack Trace

\`\`\`
$(grep "^    #" "$TRIAGE" | head -20)
\`\`\`

## Minimized Input

$(wc -c < "$MINIMIZED" | tr -d ' ') bytes — attached as \`minimized.bin\`.

## Timeline

| Date | Event |
|---|---|
| $(date +%Y-%m-%d) | Bug discovered via automated fuzzing |
| $(date +%Y-%m-%d) | Report submitted to Apple |

---
*Found with [SockFuzzer](https://github.com/kosiorkosa47/SockFuzzerAppleSilicon) — XNU kernel network stack fuzzer.*
REPORTEOF

echo "  Generated: $REPORT"
echo ""
echo "=== Pipeline Complete ==="
echo "  Report: $REPORT_DIR/"
ls -la "$REPORT_DIR/"
