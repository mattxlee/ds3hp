#!/bin/sh
set -eu

bin=$(mktemp)
tmp=$(mktemp -d)
trap 'rm -f "$bin"; rm -rf "$tmp"' EXIT
${CC:-cc} ${CFLAGS:--O2 -Wall -Wextra -Wno-unused-parameter -pthread} -o "$bin" ds3hp.c ${LDLIBS:--lm -lncursesw}

export XDG_CONFIG_HOME="$tmp/config"
mkdir -p "$XDG_CONFIG_HOME/cheat-tool"

# Missing configuration uses the built-in profile; an unknown selection fails.
"$bin" --game darksouls3 pid >/dev/null 2>&1 || test "$?" -eq 1
if "$bin" --game missing pid >"$tmp/out" 2>&1; then
    exit 1
fi
grep -q "unknown game profile 'missing'" "$tmp/out"

# Custom profile data is accepted, and unknown fields are rejected.
cat >"$XDG_CONFIG_HOME/cheat-tool/cheat-tool.json" <<'JSON'
{"games":{"fixture":{"display_name":"Fixture","process_name":"fixture-process","module_name":"fixture.bin","default_type":"int","default_min":0,"default_max":99,"default_maps":"all"}}}
JSON
if "$bin" --game fixture pid >"$tmp/out" 2>&1; then
    :
fi
cat >"$XDG_CONFIG_HOME/cheat-tool/cheat-tool.json" <<'JSON'
{"games":{"fixture":{"display_name":"Fixture","process_name":"fixture-process","module_name":"fixture.bin","default_type":"int","default_min":0,"default_max":99,"default_maps":"all","unexpected":true}}}
JSON
if "$bin" --game fixture pid >"$tmp/out" 2>&1; then
    exit 1
fi
grep -q "invalid game profile" "$tmp/out"

# Profile state paths are independent; reset does not touch another profile.
rm -f "$XDG_CONFIG_HOME/cheat-tool/cheat-tool.json"
printf 'preserve\n' >"$tmp/.cheat-tool_state.other"
(cd "$tmp" && "$bin" --game darksouls3 reset >/dev/null)
test -f "$tmp/.cheat-tool_state.other"

# Shared one-line chain text round-trips through the watch store.
line='cheat-tool-chain:v1 module="fixture.bin" type=int rva=0x123456 offsets=[0x10,0x20,0x8]'
"$bin" chain import-text Share "$line" >"$tmp/out"
"$bin" chain export-text Share >"$tmp/exported"
grep -Fqx "$line" "$tmp/exported"
if "$bin" chain import-text Share "$line" >"$tmp/out" 2>&1; then
    exit 1
fi
"$bin" chain import-text Share 'cheat-tool-chain:v1 module="new.bin" type=float rva=0x99 offsets=[0x1]' --replace
"$bin" chain export-text Share | grep -Fq 'module="new.bin" type=float rva=0x99 offsets=[0x1]'
if "$bin" chain import-text Bad 'cheat-tool-chain:v2 module="m" type=int rva=0x1 offsets=[0x2]' >"$tmp/out" 2>&1; then
    exit 1
fi
if "$bin" chain import-text Bad 'cheat-tool-chain:v1 module="m" type=bogus rva=0x1 offsets=[0x2]' >"$tmp/out" 2>&1; then
    exit 1
fi

# Optional chain defaults are accepted, and out-of-range values are rejected.
cat >"$XDG_CONFIG_HOME/cheat-tool/cheat-tool.json" <<'JSON'
{"games":{"fixture":{"display_name":"Fixture","process_name":"fixture-process","module_name":"fixture.bin","default_type":"int","default_min":0,"default_max":99,"default_maps":"all","chain_depth":2,"chain_max_offset":32768}}}
JSON
"$bin" --game fixture pid >"$tmp/out" 2>&1 || test "$?" -eq 1
if grep -q "invalid game profile" "$tmp/out"; then
    exit 1
fi
cat >"$XDG_CONFIG_HOME/cheat-tool/cheat-tool.json" <<'JSON'
{"games":{"fixture":{"display_name":"Fixture","process_name":"fixture-process","module_name":"fixture.bin","default_type":"int","default_min":0,"default_max":99,"default_maps":"all","chain_max_offset":99999999}}}
JSON
if "$bin" --game fixture pid >"$tmp/out" 2>&1; then
    exit 1
fi
grep -q "invalid game profile" "$tmp/out"

# The repository config loads and still lists both shipped games.
cp cheat-tool.json "$XDG_CONFIG_HOME/cheat-tool/cheat-tool.json"
"$bin" --game eldenring pid >"$tmp/out" 2>&1 || test "$?" -eq 1
"$bin" --game darksouls3 pid >"$tmp/out" 2>&1 || test "$?" -eq 1
if grep -q "unknown game profile" "$tmp/out"; then
    exit 1
fi

echo "tests passed"
