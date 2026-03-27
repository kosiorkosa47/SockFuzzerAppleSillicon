#!/bin/bash
set -e
EXPORT_LIST="$1"
nm -gU libxnu_relocatable_raw.o | awk '{print $NF}' | sort -u > _all_syms.txt
grep -Fx -f "$EXPORT_LIST" _all_syms.txt > _filtered_syms.txt || cp "$EXPORT_LIST" _filtered_syms.txt
nmedit -s _filtered_syms.txt -p libxnu_relocatable_raw.o -o libxnu_relocatable.o
