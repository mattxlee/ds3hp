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

echo "tests passed"
