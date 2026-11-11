#!/usr/bin/env bash
# Differential test of pry's arm64 decoder against llvm-objdump.
#
#   tests/difftest.sh [count] [seed]
#
# Assembles `count` random 32-bit words into an object file and disassembles it
# with both tools. Anything pry decodes must match llvm exactly; anything it
# doesn't is a .word and only counts against coverage. Also checks crackme0's
# functions line for line. Needs Homebrew llvm (or LLVM_OBJDUMP).
set -uo pipefail
cd "$(dirname "$0")/.."

COUNT=${1:-200000}
SEED=${2:-1}
PRY=build/pry
OBJDUMP=${LLVM_OBJDUMP:-$(brew --prefix llvm 2>/dev/null)/bin/llvm-objdump}
if [ ! -x "$OBJDUMP" ]; then
    echo "difftest: no llvm-objdump (brew install llvm, or set LLVM_OBJDUMP)" >&2
    exit 1
fi
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

# Both sides become "addr<TAB>text", with symbol annotations dropped (llvm's
# are often wrong for stubs) and whitespace collapsed.
norm_llvm() { "$OBJDUMP" -d -z --no-show-raw-insn "$@" | awk -F'\t' '
    /^ *[0-9a-f]+:/ { a = $1; sub(/^ */, "", a); sub(/:.*/, "", a)
        t = $2; for (i = 3; i <= NF; i++) t = t " " $i
        sub(/ <[^>]*>/, "", t); gsub(/  +/, " ", t); sub(/ +$/, "", t)
        print a "\t" t }'; }
norm_pry() { "$PRY" disasm "$@" | awk '
    /^ *[0-9a-f]+  [0-9a-f]{8}  / { a = $1; w = $2
        t = $0; sub(/^ *[0-9a-f]+  [0-9a-f]{8}  /, "", t)
        sub(/ <[^>]*>/, "", t); gsub(/  +/, " ", t); sub(/ +$/, "", t)
        print a "\t" w "\t" t }'; }

failed=0

S=build/samples/crackme0
for f in _main _check; do
    if diff <(norm_llvm --disassemble-symbols=$f $S | cut -f2) <(norm_pry $S $f | cut -f3) >"$T/d"; then
        echo "ok    crackme0 $f matches llvm-objdump"
    else
        echo "FAIL  crackme0 $f differs from llvm-objdump"
        cat "$T/d"
        failed=1
    fi
done

awk -v n="$COUNT" -v seed="$SEED" 'BEGIN { srand(seed); print ".text"
    for (i = 0; i < n; i++) printf ".inst 0x%04x%04x\n", int(rand() * 65536), int(rand() * 65536) }' >"$T/r.s"
cc -c -arch arm64 "$T/r.s" -o "$T/r.o" || exit 1
norm_llvm "$T/r.o" >"$T/llvm"
norm_pry "$T/r.o" >"$T/pry"

awk -F'\t' -v out="$T/miss" '
    NR == FNR { ref[$1] = $2; next }
    { theirs = ref[$1]
      if ($3 ~ /^\.word/) { unhandled++; if (theirs != "<unknown>") { split(theirs, m, " "); miss[m[1]]++ } }
      else if ($3 == theirs) ok++
      else { bad++; if (bad <= 40) printf "  0x%s  pry: %s\n              llvm: %s\n", $2, $3, theirs } }
    END {
      printf "%d matched, %d mismatched, %d left as .word\n", ok, bad, unhandled
      for (k in miss) printf "%7d %s\n", miss[k], k > out
      exit bad > 0 }' "$T/llvm" "$T/pry" >"$T/report"
rc=$?
if [ $rc -eq 0 ]; then
    echo "ok    random words (seed $SEED): $(tail -1 "$T/report")"
else
    echo "FAIL  random words (seed $SEED)"
    cat "$T/report"
    failed=1
fi
if [ -n "${VERBOSE:-}" ] && [ -s "$T/miss" ]; then
    echo "most common instructions pry leaves as .word:"
    sort -rn "$T/miss" | head -${VERBOSE}
fi

exit $failed
