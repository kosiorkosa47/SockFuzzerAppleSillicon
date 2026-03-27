#!/bin/bash
# Localize all symbols in libxnu_relocatable_raw.o except those in the export list.
# Produces libxnu_relocatable.o.
#
# Tries nmedit first (Apple toolchain). Falls back to llvm-objcopy if nmedit
# fails (e.g., Homebrew LLVM's ld -r produces objects with different string
# table layout).
set -e
EXPORT_LIST="$1"

if [ ! -f libxnu_relocatable_raw.o ]; then
  echo "ERROR: libxnu_relocatable_raw.o not found in $(pwd)" >&2
  exit 1
fi

# Build filtered symbol list (only symbols actually present in the object).
nm -gU libxnu_relocatable_raw.o | awk '{print $NF}' | sort -u > _all_syms.txt
grep -Fx -f "$EXPORT_LIST" _all_syms.txt > _filtered_syms.txt 2>/dev/null || cp "$EXPORT_LIST" _filtered_syms.txt

# Try nmedit (Apple toolchain, works with Xcode ld output).
if nmedit -s _filtered_syms.txt -p libxnu_relocatable_raw.o -o libxnu_relocatable.o 2>/dev/null; then
  exit 0
fi

# Fallback: llvm-objcopy --localize-hidden (works with LLVM ld output).
# First, mark everything hidden, then globalize the exports.
echo "nmedit failed, falling back to llvm-objcopy..." >&2
OBJCOPY=$(command -v llvm-objcopy || echo "$(brew --prefix llvm 2>/dev/null)/bin/llvm-objcopy")
if [ -x "$OBJCOPY" ]; then
  cp libxnu_relocatable_raw.o libxnu_relocatable.o
  # Build --globalize-symbol args from the export list
  GLOBAL_ARGS=""
  while IFS= read -r sym; do
    GLOBAL_ARGS="$GLOBAL_ARGS --globalize-symbol=$sym"
  done < _filtered_syms.txt
  $OBJCOPY --localize-hidden $GLOBAL_ARGS libxnu_relocatable.o 2>/dev/null || {
    echo "WARNING: llvm-objcopy failed, using raw object without symbol localization" >&2
    cp libxnu_relocatable_raw.o libxnu_relocatable.o
  }
else
  echo "WARNING: neither nmedit nor llvm-objcopy available, using raw object" >&2
  cp libxnu_relocatable_raw.o libxnu_relocatable.o
fi
