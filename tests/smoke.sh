#!/usr/bin/env bash
# Checks pry against Apple's own tools on the sample binaries. macOS only.
set -uo pipefail
cd "$(dirname "$0")/.."

PRY=build/pry
S=build/samples/crackme0
failed=0

check() {
    local name=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo "ok    $name"
    else
        echo "FAIL  $name"
        failed=1
    fi
}

addrs() { "$PRY" funcs "$1" | grep -oE '^0x[0-9a-f]+'; }

check "syms match nm -n" \
    diff <("$PRY" syms $S | grep -E '^[0-9a-f]{16}' | awk '{print $1, $2, $3}') <(nm -n $S | grep -v ' U ')
check "sections match otool -l" \
    diff <("$PRY" sections $S | grep -oE '^ +\[ *[0-9]+\] +[^ ]+' | awk '{print $NF}') <(otool -l $S | awk '/sectname/ {print $2}')
check "load commands match otool -l" \
    diff <("$PRY" lc $S | awk '{print $3}') <(otool -l $S | awk '/^ +cmd / {print $2}')
check "imports name their dylib" grep -q '_strcmp  (libSystem.B.dylib)' <("$PRY" syms $S)
check "entry point resolves to _main" grep -qE '^entry +0x[0-9a-f]+  _main$' <("$PRY" info $S)
check "funcs survive strip" diff <(addrs $S) <(addrs $S.stripped)
check "stripped funcs are unnamed" grep -q '2 functions, 2 without a symbol' <("$PRY" funcs $S.stripped)
check "strings finds literals" grep -q '"access granted"' <("$PRY" strings $S)
check "hex resolves symbols" grep -qE '^[0-9a-f]{16}  ' <("$PRY" hex $S _main 16)
check "fat file picks requested slice" grep -qE '^arch +x86_64$' <("$PRY" -a x86_64 info /bin/ls)
check "missing slice is an error" bash -c "! '$PRY' -a i386 info /bin/ls"
check "non-Mach-O is rejected" bash -c "'$PRY' info Makefile 2>&1 | grep -q 'not a Mach-O'"

exit $failed
