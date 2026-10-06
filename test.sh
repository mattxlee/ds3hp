#!/bin/sh
set -eu

bin=$(mktemp)
tmp=$(mktemp -d)
trap 'rm -f "$bin"; rm -rf "$tmp"' EXIT
${CC:-cc} ${CFLAGS:--O2 -Wall -Wextra -Wno-unused-parameter -pthread} -o "$bin" ds3hp.c ${LDLIBS:--lm -lncursesw}

export HOME="$tmp/home"
export XDG_CONFIG_HOME="$tmp/config"
mkdir -p "$HOME" "$XDG_CONFIG_HOME/cheat-tool"

write_fixture_profile()
{
    cat >"$XDG_CONFIG_HOME/cheat-tool/cheat-tool.json" <<'JSON'
{"games":{"fixture":{"display_name":"Fixture","process_name":"fixture-process","module_name":"fixture.bin","default_type":"int","default_min":0,"default_max":99,"default_maps":"all"}}}
JSON
}

# Missing configuration uses the built-in profile; an unknown selection fails.
"$bin" --game darksouls3 pid >/dev/null 2>&1 || test "$?" -eq 1
if "$bin" --game missing pid >"$tmp/out" 2>&1; then
    exit 1
fi
grep -q "unknown game profile 'missing'" "$tmp/out"

# Custom profile data is accepted, and unknown fields are rejected.
write_fixture_profile
"$bin" --game fixture pid >"$tmp/out" 2>&1 || test "$?" -eq 1
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

# Explicit chain PIDs are rejected before maps access if they do not match.
write_fixture_profile
for args in \
    "chain scan A --addr 0x1 --pid $$" \
    "chain list A --pid $$" \
    "chain resolve A --pid $$" \
    "chain verify A --value 1 --pid $$" \
    "chain load A --pid $$"; do
    if "$bin" --game fixture $args >"$tmp/out" 2>&1; then
        exit 1
    fi
    grep -q "does not match profile 'fixture'" "$tmp/out"
done

# Legacy JSON migration honors XDG_CONFIG_HOME and preserves its source.
rm -f "$XDG_CONFIG_HOME/cheat-tool/cheat-tool.json"
mkdir -p "$XDG_CONFIG_HOME/ds3hp"
printf '{"_version":1,"Legacy":{"type":"int","lock_value":42,"lock_on":false}}\n' \
    >"$XDG_CONFIG_HOME/ds3hp/watches.json"
"$bin" --game darksouls3 chain list >"$tmp/out"
target="$XDG_CONFIG_HOME/cheat-tool/games/darksouls3/watches.json"
grep -q 'Legacy' "$tmp/out"
grep -q 'Legacy' "$target"
test -f "$XDG_CONFIG_HOME/ds3hp/watches.json"

# An existing target, even empty, is authoritative and is never overwritten.
printf '{"_version":1}\n' >"$target"
printf '{"_version":1,"Legacy":{"type":"int","lock_value":99,"lock_on":false}}\n' \
    >"$XDG_CONFIG_HOME/ds3hp/watches.json"
"$bin" --game darksouls3 chain list >"$tmp/out"
if grep -q 'Legacy' "$tmp/out"; then
    exit 1
fi
if grep -q '99' "$target"; then
    exit 1
fi

# HOME fallback is used for the legacy JSON source when XDG is unset.
rm -rf "$target" "$XDG_CONFIG_HOME/ds3hp"
mkdir -p "$HOME/.config/ds3hp"
printf '{"_version":1,"HomeOld":{"type":"int","lock_value":7,"lock_on":false}}\n' \
    >"$HOME/.config/ds3hp/watches.json"
(cd "$tmp" && env -u XDG_CONFIG_HOME "$bin" --game darksouls3 chain list >"$tmp/out")
grep -q 'HomeOld' "$tmp/out"
test -f "$HOME/.config/ds3hp/watches.json"

# Shared one-line chain text round-trips through the watch store.
write_fixture_profile
line='cheat-tool-chain:v1 module="fixture.bin" type=int rva=0x123456 offsets=[0x10,0x20,0x8]'
"$bin" --game fixture chain import-text Share "$line" >"$tmp/out"
"$bin" --game fixture chain export-text Share >"$tmp/exported"
grep -Fqx "$line" "$tmp/exported"
if "$bin" --game fixture chain import-text Share "$line" >"$tmp/out" 2>&1; then
    exit 1
fi
"$bin" --game fixture chain import-text Share 'cheat-tool-chain:v1 module="new.bin" type=float rva=0x99 offsets=[0x1]' --replace
"$bin" --game fixture chain export-text Share | grep -Fq 'module="new.bin" type=float rva=0x99 offsets=[0x1]'
if "$bin" --game fixture chain import-text Bad 'cheat-tool-chain:v2 module="m" type=int rva=0x1 offsets=[0x2]' >"$tmp/out" 2>&1; then
    exit 1
fi
if "$bin" --game fixture chain import-text Bad 'cheat-tool-chain:v1 module="m" type=bogus rva=0x1 offsets=[0x2]' >"$tmp/out" 2>&1; then
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

# Exercise TUI profile-default helpers without ncurses or a game process.
cat >"$tmp/defaults_test.c" <<EOF
#define main cheat_tool_main
#include "$PWD/ds3hp.c"
#undef main
int main(void)
{
    Search s = {0};
    g_profile.min = 37;
    g_profile.max = 83;
    g_profile.anon_only = 0;
    tui_first_defaults(&s);
    if (s.min != 37 || s.max != 83 || s.exact || s.tol != 0 || profile_anon_only())
        return 1;

    g_profile = (GameProfile){"darksouls3", "Dark Souls III", "DarkSoulsIII",
                              "DarkSoulsIII.exe", T_FLOAT, 1, 10000, 1,
                              CHAIN_DEF_DEPTH, CHAIN_DEF_OFF};
    char path[768];
    snprintf(path, sizeof path, "%s", watches_path());
    char dir[768];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (!slash)
        return 1;
    *slash = 0;
    mkdir_p(dir);
    FILE *f = fopen(path, "wb");
    if (!f)
        return 1;
    fputs("{\"_version\":1}\n", f);
    fclose(f);
    f = fopen(".ds3hp_watches", "w");
    if (!f)
        return 1;
    fputs("DS3HPW1\nTextOld\t1\t1\t7\t0\n", f);
    fclose(f);
    watches_load();
    if (g_nw != 0)
        return 1;
    unlink(".ds3hp_watches");
    unlink(path);

    g_nw = 0;
    f = fopen(".ds3hp_watches", "w");
    if (!f)
        return 1;
    fputs("DS3HPW1\nTextOld\t1\t1\t7\t0\n", f);
    fclose(f);
    watches_load();
    if (g_nw != 1 || strcmp(g_w[0].name, "TextOld") != 0)
        return 1;
    unlink(".ds3hp_watches");
    unlink(path);
    return 0;
}
EOF
${CC:-cc} ${CFLAGS:--O2 -Wall -Wextra -Wno-unused-parameter -pthread} \
    -o "$tmp/defaults_test" "$tmp/defaults_test.c" ${LDLIBS:--lm -lncursesw}
(cd "$tmp" && "$tmp/defaults_test")

echo "tests passed"
