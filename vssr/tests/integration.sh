#!/usr/bin/env bash
# End-to-end checks of the sandbox's guarantees. Run after `cargo build`:
#   tests/integration.sh [path/to/vssr]
# Network tests need internet access and are skipped with VSSR_TEST_OFFLINE=1.
# Resource-limit tests need a systemd user manager.
set -u

V=${1:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/vssr}
V=$(realpath "$V")
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vssr-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
cd "$WORK" || exit 1
mkdir proj && cd proj || exit 1

pass=0 fail=0
ok()   { pass=$((pass + 1)); printf ' ok   %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf ' FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '      %s\n' "$2"; }
# expect NAME EXPECTED_EXIT -- vssr args...
expect() {
    local name=$1 want=$2; shift 3
    local out; out=$("$V" "$@" 2>&1); local got=$?
    if [ "$got" = "$want" ]; then ok "$name"; else bad "$name" "exit $got, wanted $want: $(echo "$out" | tail -n 3 | tr '\n' ' ')"; fi
}
# expect_out NAME REGEX -- vssr args...   (stdout+stderr must match)
expect_out() {
    local name=$1 re=$2; shift 3
    local out; out=$("$V" "$@" 2>&1)
    if echo "$out" | grep -Eq -- "$re"; then ok "$name"; else bad "$name" "output: $(echo "$out" | tail -n 4 | tr '\n' ' ')"; fi
}

echo "== basics"
expect "runs a command"                0   -- run -- true
expect "propagates exit codes"         42  -- run -- sh -c 'exit 42'
expect "reports death by signal"       137 -- run -- sh -c 'kill -9 $$'
expect "command not found is 127"      127 -- run -- /nonexistent/cmd
"$V" run --audit-log "$WORK/setup.jsonl" -- /nonexistent/cmd >/dev/null 2>&1
grep '"event":"setup_failed"' "$WORK/setup.jsonl" | grep -q '"code":127' && ! grep -q '"event":"start"' "$WORK/setup.jsonl" \
    && ok "setup failures are audited, not started" || bad "setup failures are audited, not started" "$(cat "$WORK/setup.jsonl" 2>/dev/null)"
echo keep > "$WORK/audit-sentinel"; ln -s "$WORK/audit-sentinel" audit.jsonl
expect "a symlinked audit log is refused" 125 -- run --audit-log audit.jsonl -- true
[ "$(cat "$WORK/audit-sentinel")" = keep ] && ok "  ...and its target is untouched" || bad "  ...and its target is untouched"
mkdir -p "$WORK/audit-dir"; ln -s "$WORK/audit-dir" logs
expect "  ...and so is a symlinked directory in a writable one" 125 -- run --audit-log logs/a.jsonl -- true
[ -z "$(ls -A "$WORK/audit-dir")" ] && ok "  ...which stays empty" || bad "  ...which stays empty"
expect "  ...also reached through a missing directory and \"..\"" 125 -- run --audit-log missing/../logs/created/a.jsonl -- true
[ -z "$(ls -A "$WORK/audit-dir")" ] && [ ! -e missing ] && ok "  ...which creates nothing" || bad "  ...which creates nothing" "$(ls -A "$WORK/audit-dir") $(ls -d missing 2>/dev/null)"
mkfifo audit.fifo
timeout 10 "$V" run --audit-log audit.fifo -- true >/dev/null 2>&1; [ $? = 125 ] && ok "a FIFO as the audit log is refused, without hanging" || bad "a FIFO as the audit log is refused, without hanging"
rm -f audit.jsonl logs audit.fifo
( cd ~ && "$V" run -- true >/dev/null 2>&1 ); [ $? = 125 ] && ok "refuses to run from \$HOME with the default policy" || bad "refuses to run from \$HOME with the default policy"
expect_out "own PID namespace"         '^2$' -- run -- sh -c 'echo $$'
expect_out "own hostname"              '^vssr$' -- run -- cat /proc/sys/kernel/hostname
expect_out "runs as the host uid"      "^$(id -u)\$" -- run -- id -u
expect_out "host processes invisible"  '^[0-9]$' -- run -- sh -c 'ls /proc | grep -c "^[0-9]"'
expect_out "SIGPIPE has its default"   '^141$' -- run -- bash -c 'yes | head -1 >/dev/null; echo ${PIPESTATUS[0]}'

echo "== filesystem"
expect "cwd is writable"               0   -- run -- sh -c 'echo hi > out.txt'
[ "$(cat out.txt 2>/dev/null)" = hi ] && ok "writes reach the host" || bad "writes reach the host"
[ "$(stat -c %u out.txt)" = "$(id -u)" ] && ok "files are owned by the host user" || bad "files are owned by the host user"
expect "/usr is read-only"             1   -- run -- touch /usr/vssr-x
expect "/etc is read-only"             1   -- run -- touch /etc/vssr-x
expect "the root is read-only"         1   -- run -- touch /vssr-x
expect "home is empty"                 2   -- run -- ls ~/.ssh
echo secret > "$WORK/host-secret"
expect "unlisted host paths are invisible" 1 -- run -- cat "$WORK/host-secret"
expect "/tmp is private"               1   -- run -- cat "$WORK/host-secret"
mkdir -p data && echo d > data/f
expect "--ro is read-only"             1   -- run --ro "$PWD/data" -- sh -c 'echo x > data/f'
expect "--ro is readable"              0   -- run --ro "$PWD/data" -- cat data/f
echo topsecret > .env
expect "--deny hides a file"           1   -- run --deny "$PWD/.env" -- cat .env
mkdir -p .git && echo cfg > .git/config
expect "--deny hides a directory"      2   -- run --deny "$PWD/.git" -- ls .git
expect "denied paths stay hidden when written to" 1 -- run --deny "$PWD/.env" -- sh -c 'echo x > .env'
[ "$(cat .env)" = topsecret ] && ok "denied file untouched on the host" || bad "denied file untouched on the host"
expect "--tmpfs over part of cwd"      0   -- run --tmpfs "$PWD/data" -- sh -c 'test ! -e data/f && touch data/new'
[ ! -e data/new ] && ok "tmpfs writes stay in the sandbox" || bad "tmpfs writes stay in the sandbox"
ln -sf ~/.ssh sneaky
expect "won't follow symlinks in writable dirs" 125 -- run --ro "$PWD/sneaky" -- true
ln -sf /usr/bin/true data/sym 2>/dev/null
expect "won't mount through symlinks"  125 -- run --tmpfs "$PWD/sneaky/x" -- true
# Two spellings of one writable directory (alias -> real), and a symlink an
# earlier run could have planted in it.
mkdir -p "$WORK/real/work/sub" "$WORK/planted-target" && ln -s real "$WORK/alias"
ln -s "$WORK/planted-target" "$WORK/real/work/planted"; echo s > "$WORK/real/work/sub/f"
expect "no symlinks in a writable dir named through an alias" 125 -- run --rw "$WORK/alias/work:/work" --ro "$WORK/real/work/planted:/exposed" -- true
expect "  ...nor the reverse"          125 -- run --rw "$WORK/real/work:/work" --ro "$WORK/alias/work/planted:/exposed" -- true
expect "symlinks above a writable dir are followed" 0 -- run --rw "$WORK/alias/work" --ro "$WORK/alias/work/sub" -- cat "$WORK/alias/work/sub/f"
expect "ro .git inside a writable checkout" 1 -- run --ro "$PWD/.git" -- sh -c 'echo x > .git/config'
expect "  ...while the rest stays writable" 0 -- run --ro "$PWD/.git" -- sh -c 'echo x > ok.txt'
# A host socket exposed read-only outside any writable path (think docker.sock).
mkdir -p ../hs
( cd .. && python3 -c '
import socket,time
s=socket.socket(socket.AF_UNIX); s.bind("hs/s"); s.listen(); time.sleep(5)' ) &
sp=$!
sleep 0.3
expect_out "no connecting to host unix sockets" 'Errno 13|Errno 1' -- run --ro "$WORK/hs" -- python3 -c 'import socket
s=socket.socket(socket.AF_UNIX)
try: s.connect("../hs/s"); print("connected")
except OSError as e: print(e)'
kill $sp 2>/dev/null
expect_out "agents can use their own unix sockets" '^ok$' -- run -- python3 -c 'import socket,os
p="/tmp/own.sock"; s=socket.socket(socket.AF_UNIX); s.bind(p); s.listen()
c=socket.socket(socket.AF_UNIX); c.connect(p); print("ok")'
cat > noexec.toml <<EOF
[fs]
rw = ["\$PWD"]
noexec = ["\$PWD"]
EOF
cp /usr/bin/true ./mytrue
expect "noexec blocks binaries"        126 -- run -p noexec.toml -- ./mytrue
expect "/dev/null works"               0   -- run -- sh -c 'echo x > /dev/null'
expect "ptys work"                     0   -- run -- python3 -c 'import pty; pty.openpty()'

echo "== attacks from another sandbox"
# A plants a symlink in the project for a later run to follow.
expect "a sandbox can plant a symlink in its project" 0 -- run -- ln -s "$WORK/host-secret" planted
ln -s proj "$WORK/proj-alias"; mkdir -p "$WORK/elsewhere"
out=$(cd "$WORK/elsewhere" && "$V" run --rw "$WORK/proj-alias" --ro "$WORK/proj/planted:/exposed" -- cat /exposed 2>/dev/null); code=$?
[ $code = 125 ] && [ -z "$out" ] && ok "  ...which a later run, writing the project by another name, refuses" \
    || bad "  ...which a later run, writing the project by another name, refuses" "exit $code: $out"
rm -f planted
# A runs in the same directory as B (both can write it, like two agents in
# one project), plants symlinks to host paths it can't see and keeps
# swapping them (renameat2 RENAME_EXCHANGE) with what B binds or logs to.
R="$WORK/race"
mkdir -p "$R/x" "$R/p/x" "$R/logs" "$WORK/race-secret/x" "$WORK/race-logs"
echo real > "$R/x/f"; echo real > "$R/p/x/f"
echo secret > "$WORK/race-secret/f"; echo secret > "$WORK/race-secret/x/f"
echo keep > "$WORK/race-sentinel"; : > "$R/log.jsonl"
cat > "$R/swap.py" <<'EOF'
# swap.py NAME=TARGET...: plants NAME.swap -> TARGET for each, then swaps
# NAME and NAME.swap over and over until ./stop appears.
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
names = []
for a in sys.argv[1:]:
    n, t = a.split("=", 1)
    os.symlink(t, n + ".swap")
    names.append(n.encode())
print("swapping", flush=True)
swaps = 0
while not os.path.exists("stop"):
    for n in names:
        if libc.renameat2(-100, n, -100, n + b".swap", 2) != 0:
            sys.exit("renameat2: " + os.strerror(ctypes.get_errno()))
    swaps += 1
print(swaps)
EOF
( cd "$R" && exec timeout 300 "$V" run -- python3 swap.py "x=$WORK/race-secret" "p=$WORK/race-secret" \
    "log.jsonl=$WORK/race-sentinel" "logs=$WORK/race-logs" ) > "$WORK/race-a.out" 2>&1 &
apid=$!
for _ in $(seq 100); do grep -q swapping "$WORK/race-a.out" && break; sleep 0.1; done
if grep -q swapping "$WORK/race-a.out"; then
    # B binds R/x (swapped itself) and R/p/x (a directory above it swapped).
    # vssr refuses a symlink it sees; vssb one swapped in after that.
    real=0 policy=0 child=0 leaked=0 other=
    for i in $(seq 400); do
        out=$(cd "$R" && "$V" run --ro "$R/x:/mnt/x" --ro "$R/p/x:/mnt/y" -- cat /mnt/x/f /mnt/y/f 2>"$WORK/race-b.err"); code=$?
        err=$(cat "$WORK/race-b.err")
        if [[ $out == *secret* ]]; then leaked=$((leaked + 1))
        elif [ $code = 0 ] && [ "$out" = "$(printf 'real\nreal')" ]; then real=$((real + 1))
        elif [ $code = 125 ] && [[ $err == *"refusing to follow the symlink"* ]]; then policy=$((policy + 1))
        elif [ $code = 125 ] && [[ $err == *"has a symlink in its path"* ]]; then child=$((child + 1))
        else other="exit $code: $out $err"; fi
        [ $real -gt 0 ] && [ $policy -gt 0 ] && [ $child -gt 0 ] && [ $i -ge 30 ] && break
    done
    counts="$real exposed, $policy refused by vssr, $child refused by vssb, $leaked leaked"
    [ $leaked = 0 ] && [ -z "$other" ] && ok "binds can't be redirected by another sandbox ($counts)" \
        || bad "binds can't be redirected by another sandbox" "$counts; $other"
    [ $real -gt 0 ] && [ $policy -gt 0 ] && [ $child -gt 0 ] && ok "  ...which raced both checks" \
        || bad "  ...which raced both checks" "$counts"
    # B's audit log: the file swapped with a symlink to a host file, and a
    # directory above it swapped with one to a host directory, also while
    # B creates a directory in it.
    logged=0 refused=0 other=
    for i in $(seq 400); do
        for log in log.jsonl logs/a.jsonl "logs/new$i/a.jsonl"; do
            (cd "$R" && "$V" run --audit-log "$R/$log" -- true) >/dev/null 2>"$WORK/race-b.err"; code=$?
            if [ $code = 0 ]; then logged=$((logged + 1))
            elif [ $code = 125 ] && grep -Eq 'symlink|symbolic link' "$WORK/race-b.err"; then refused=$((refused + 1))
            else other="$log: exit $code: $(cat "$WORK/race-b.err")"; fi
        done
        [ $logged -gt 0 ] && [ $refused -gt 0 ] && [ $i -ge 15 ] && break
    done
    counts="$logged logged, $refused refused"
    [ "$(cat "$WORK/race-sentinel")" = keep ] && [ -z "$(ls -A "$WORK/race-logs")" ] && [ -z "$other" ] \
        && ok "the audit log can't be redirected by another sandbox ($counts)" \
        || bad "the audit log can't be redirected by another sandbox" "$counts; $other; $(ls -A "$WORK/race-logs")"
    [ $logged -gt 0 ] && [ $refused -gt 0 ] && ok "  ...which raced its checks" || bad "  ...which raced its checks" "$counts"
fi
touch "$R/stop"; wait $apid; acode=$?
swaps=$(tail -n 1 "$WORK/race-a.out")
[ $acode = 0 ] && [[ $swaps =~ ^[0-9]+$ ]] && [ "$swaps" -gt 0 ] && ok "the attacking sandbox kept swapping ($swaps rounds)" \
    || bad "the attacking sandbox kept swapping" "exit $acode: $(cat "$WORK/race-a.out")"
# A keeps planting and removing logs -> a host directory while B logs to
# logs/new/a.jsonl, so logs is often missing when vssr checks the path and
# a symlink by the time it creates the directory.
R2="$WORK/race2"
mkdir -p "$R2" "$WORK/race2-outside"
cat > "$R2/plant.py" <<'EOF'
# plant.py NAME TARGET: creates and removes NAME -> TARGET over and over
# until ./stop appears.
import os, sys
name, target = sys.argv[1:]
print("planting", flush=True)
planted = 0
while not os.path.exists("stop"):
    try:
        os.symlink(target, name)
    except FileExistsError:
        continue  # B's real directory, until the test removes it
    planted += 1
    try:
        os.unlink(name)
    except OSError:
        pass
print(planted)
EOF
( cd "$R2" && exec timeout 300 "$V" run -- python3 plant.py logs "$WORK/race2-outside" ) > "$WORK/race2-a.out" 2>&1 &
apid=$!
for _ in $(seq 100); do grep -q planting "$WORK/race2-a.out" && break; sleep 0.1; done
if grep -q planting "$WORK/race2-a.out"; then
    logged=0 seen=0 during=0 other=
    for i in $(seq 400); do
        (cd "$R2" && "$V" run --audit-log "$R2/logs/new/a.jsonl" -- true) >/dev/null 2>"$WORK/race-b.err"; code=$?
        err=$(cat "$WORK/race-b.err")
        if [ $code = 0 ]; then
            logged=$((logged + 1))
            rm -rf "$R2/logs" # B's real directory: start again with it missing
        elif [ $code = 125 ] && [[ $err == *"inside the writable directory"* ]]; then seen=$((seen + 1))
        elif [ $code = 125 ] && [[ $err == *"may have planted it"* || $err == *"No such file"* ]]; then during=$((during + 1))
        else other="exit $code: $err"; fi
        [ -n "$(ls -A "$WORK/race2-outside")" ] && break
        [ $logged -gt 0 ] && [ $seen -gt 0 ] && [ $during -gt 0 ] && [ $i -ge 30 ] && break
    done
    counts="$logged logged, $seen refused when checked, $during refused while creating"
    [ -z "$(ls -A "$WORK/race2-outside")" ] && [ -z "$other" ] \
        && ok "a symlink planted at a missing log directory isn't followed ($counts)" \
        || bad "a symlink planted at a missing log directory isn't followed" "$counts; $other; created: $(ls -A "$WORK/race2-outside")"
    [ $logged -gt 0 ] && [ $seen -gt 0 ] && [ $during -gt 0 ] && ok "  ...which raced the check and the creation" \
        || bad "  ...which raced the check and the creation" "$counts"
fi
touch "$R2/stop"; wait $apid; acode=$?
planted=$(tail -n 1 "$WORK/race2-a.out")
[ $acode = 0 ] && [[ $planted =~ ^[0-9]+$ ]] && [ "$planted" -gt 0 ] && ok "the planting sandbox kept planting ($planted symlinks)" \
    || bad "the planting sandbox kept planting" "exit $acode: $(cat "$WORK/race2-a.out")"

echo "== detection (cargo)"
# ws/app depends on ../lib (which depends on ../lib2), on a member of the
# workspace ws/other, and on ../../outside, which is outside detect.within;
# its member crates/m depends on ../../../mdep.
D="$WORK/ws"
mkdir -p "$D/app/crates/m" "$D/lib" "$D/lib2" "$D/other/crates/x" "$D/mdep" "$WORK/outside"
printf '%s\n' '[package]' 'name = "app"' '[dependencies]' 'lib = { path = "../lib" }' \
    'o = { path = "../../outside" }' 'v = { path = "vendor" }' '[dev-dependencies]' \
    'x = { path = "../other/crates/x" }' '[workspace]' 'members = ["crates/*"]' > "$D/app/Cargo.toml"
printf '%s\n' '[package]' 'name = "m"' '[dependencies]' 'mdep = { path = "../../../mdep" }' > "$D/app/crates/m/Cargo.toml"
printf '%s\n' '[package]' 'name = "lib"' '[dependencies]' 'lib2 = { path = "../lib2" }' > "$D/lib/Cargo.toml"
printf '%s\n' '[package]' 'name = "lib2"' > "$D/lib2/Cargo.toml"
printf '%s\n' '[workspace]' 'members = ["crates/*"]' > "$D/other/Cargo.toml"
printf '%s\n' '[package]' 'name = "x"' > "$D/other/crates/x/Cargo.toml"
for d in lib lib2 other mdep; do echo "$d" > "$D/$d/marker"; done
echo secret > "$WORK/outside/secret"
# A symlink inside the writable project must not smuggle in other paths.
ln -s "$WORK/outside" "$D/app/vendor"
cd "$D/app" || exit 1
expect "detected paths need detect.within"   1 -- run -- cat ../lib/marker
expect_out "  ...and say how to allow them"  'outside detect.within' -- run -- true
W=(--detect-within "$D")
expect "path dependencies are exposed"       0 -- run "${W[@]}" -- cat ../lib/marker
expect "  ...transitively"                   0 -- run "${W[@]}" -- cat ../lib2/marker
expect "  ...of workspace members"           0 -- run "${W[@]}" -- cat ../mdep/marker
expect "a dependency's workspace root is exposed" 0 -- run "${W[@]}" -- cat ../other/marker
expect "detected paths are read-only"        1 -- run "${W[@]}" -- touch ../lib/x
expect "nothing outside detect.within"       1 -- run "${W[@]}" -- cat ../../outside/secret
expect "no smuggling through symlinks"       1 -- run "${W[@]}" -- cat vendor/secret
expect "deny beats detection"                1 -- run "${W[@]}" --deny "$D/lib" -- cat ../lib/marker
expect "--no-detect turns it off"            1 -- run "${W[@]}" --no-detect -- cat ../lib/marker
expect_out "dry run shows why"               'ro +.*/ws/lib +\(detected: path dependency of app\)' -- run "${W[@]}" --dry-run -- true
WR=(--detect-within-rw "$D")
expect "detect.within_rw makes them writable" 0 -- run "${WR[@]}" -- touch ../lib/rw-test
[ -e "$D/lib/rw-test" ] && ok "  ...and writes reach the host" || bad "  ...and writes reach the host"
expect "  ...transitively"                   0 -- run "${WR[@]}" -- touch ../lib2/rw-test
expect "  ...still nothing outside it"       1 -- run "${WR[@]}" -- cat ../../outside/secret
# ws/other (a dependency's workspace root) contains the dependency crates/x.
expect "the deepest root decides: rw parent"  0 -- run "${WR[@]}" --detect-within "$D/other/crates" -- touch ../other/rw-test
expect "  ...with a read-only child"         1 -- run "${WR[@]}" --detect-within "$D/other/crates" -- touch ../other/crates/x/rw-test
expect "  ...and the reverse: ro parent"     1 -- run "${W[@]}" --detect-within-rw "$D/other/crates" -- touch ../other/rw-test2
expect "  ...with a writable child"          0 -- run "${W[@]}" --detect-within-rw "$D/other/crates" -- touch ../other/crates/x/rw-test
expect "an explicit --ro beats within_rw"    1 -- run "${WR[@]}" --ro "$D/lib" -- touch ../lib/rw-test2
expect_out "  ...also from a parent, with a note" 'stays read-only' -- run "${WR[@]}" --ro "$D" -- true
ln -s "$WORK/outside" "$D/lnk"
expect "no following symlinks under within_rw" 125 -- run "${WR[@]}" --ro "$D/lnk" -- true
rm -f "$D/lnk" "$D"/*/rw-test "$D/other/crates/x/rw-test"
cd "$D/other/crates/x" || exit 1
expect_out "warns about a workspace root above the cwd" 'workspace root of .*run vssr from' -- run -- true
# A git repository: repo/app depends on repo/lib, and (as an edited build
# file might) on the repository root and its .git.
R="$WORK/repo"
mkdir -p "$R/.git/hooks" "$R/app" "$R/lib"; echo root > "$R/rootfile"
printf '%s\n' '[package]' 'name = "app"' '[dependencies]' 'lib = { path = "../lib" }' \
    'g = { path = "../.git/hooks" }' 'r = { path = ".." }' > "$R/app/Cargo.toml"
echo lib > "$R/lib/marker"
cd "$R/app" || exit 1
expect "same-repo dependencies are exposed by default" 0 -- run -- cat ../lib/marker
expect "  ...read-only by default"           1 -- run -- touch ../lib/rw-test
expect "--detect-project rw makes them writable" 0 -- run --detect-project rw -- touch ../lib/rw-test
[ -e "$R/lib/rw-test" ] && ok "  ...and writes reach the host" || bad "  ...and writes reach the host"
expect "--detect-project off turns it off"   1 -- run --detect-project off -- cat ../lib/marker
expect "never the repository's .git"         1 -- run --detect-project rw -- test -e ../.git
expect "  ...nor the repository root"        1 -- run --detect-project rw -- cat ../rootfile
expect "within_rw still widens a ro project" 0 -- run --detect-within-rw "$R/lib" -- touch ../lib/rw-test2
HOME="$R" "$V" run --detect-project rw -- cat ../lib/marker >/dev/null 2>&1
[ $? = 1 ] && ok "a repository at \$HOME is not a project" || bad "a repository at \$HOME is not a project"
rm -f "$R/lib"/rw-test*
cd "$WORK/proj" || exit 1

echo "== syscalls"
expect "no nested user namespaces"     1   -- run -- unshare -r true
expect_out "no ptrace"                 'Operation not permitted' -- run -- python3 -c 'import ctypes,os; l=ctypes.CDLL(None,use_errno=True); l.ptrace(16,1,0,0); print(os.strerror(ctypes.get_errno()))'
expect_out "no TIOCSTI"                'Errno 1' -- run -- python3 -c 'import fcntl,termios
try: fcntl.ioctl(0, termios.TIOCSTI, b"x")
except OSError as e: print(e)'
expect_out "no raw packet sockets"     'Errno 97' -- run -- python3 -c 'import socket
try: socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
except OSError as e: print(e)'
expect_out "no io_uring"               'Errno 1' -- run -- python3 -c 'import ctypes,os; l=ctypes.CDLL(None,use_errno=True); p=ctypes.create_string_buffer(120); r=l.syscall(425,8,p); print("Errno",ctypes.get_errno())'
expect "threads work (clone3 fallback)" 0  -- run -- python3 -c 'import threading; t=threading.Thread(target=print); t.start(); t.join()'
expect_out "PID 1 memory is off limits" 'Permission denied' -- run -- cat /proc/1/environ
expect "no setuid escalation"          1   -- run -- sudo -n true
cat > ptrace.toml <<EOF
[fs]
rw = ["\$PWD"]
[seccomp]
allow = ["ptrace"]
EOF
expect_out "seccomp.allow re-enables a syscall" 'Success|Operation not permitted|No such process' -- run -p ptrace.toml -- python3 -c 'import ctypes,os; l=ctypes.CDLL(None,use_errno=True); r=l.ptrace(0,0,0,0); print(r, os.strerror(ctypes.get_errno()))'

echo "== environment"
export VSSR_TEST_SECRET=hunter2
expect "secrets aren't passed by default" 1 -- run -- sh -c 'test -n "${VSSR_TEST_SECRET:-}"'
expect "-e passes a variable"          0   -- run -e VSSR_TEST_SECRET -- sh -c 'test "$VSSR_TEST_SECRET" = hunter2'
expect "-e sets a variable"            0   -- run -e FOO=bar -- sh -c 'test "$FOO" = bar'

echo "== lifecycle"
start=$(date +%s)
expect "timeout exits 124"             124 -- run --timeout 1 -- sleep 30
[ $(( $(date +%s) - start )) -lt 5 ] && ok "timeout is prompt" || bad "timeout is prompt"
cat > grace.toml <<EOF
[sandbox]
kill_grace = "1s"
[fs]
rw = ["\$PWD"]
EOF
start=$(date +%s)
expect "SIGTERM-ignoring agents are killed" 124 -- run -p grace.toml --timeout 1 -- sh -c 'trap "" TERM; while :; do sleep 0.1; done'
[ $(( $(date +%s) - start )) -lt 6 ] && ok "kill after grace is prompt" || bad "kill after grace is prompt"
"$V" run -- sh -c 'sleep 4242 & echo started' >/dev/null 2>&1
sleep 0.3
pgrep -f '^sleep 4242$' >/dev/null && bad "leftover processes are killed" || ok "leftover processes are killed"
"$V" run -- sleep 4343 >/dev/null 2>&1 &
sup=$!
sleep 0.5
kill -9 "$sup"; wait "$sup" 2>/dev/null
sleep 0.5
pgrep -f '^sleep 4343$' >/dev/null && bad "sandbox dies with its supervisor" || ok "sandbox dies with its supervisor"
"$V" run -- sh -c 'trap "echo got-term; exit 3" TERM; sleep 5 & wait' > sig.out 2>&1 &
sup=$!
sleep 0.5
kill -TERM "$sup"; wait "$sup"; code=$?
grep -q got-term sig.out && [ $code = 3 ] && ok "SIGTERM is forwarded to the agent" || bad "SIGTERM is forwarded to the agent" "exit $code: $(cat sig.out)"
# Background jobs of a script start with SIGINT ignored; undo that.
env --default-signal=INT "$V" run --tty -- sh -c 'trap "echo got-int; exit 3" INT; sleep 5 & wait' > sig.out 2>&1 &
sup=$!
sleep 1
kill -INT "$sup"; wait "$sup"; code=$?
grep -q got-int sig.out && [ $code = 3 ] && ok "with --tty, a SIGINT from kill is still forwarded" || bad "with --tty, a SIGINT from kill is still forwarded" "exit $code: $(cat sig.out)"
expect "an unrepresentable timeout is a config error" 125 -- run --timeout 1e300 --dry-run -- true
expect "a timeout beyond the clock's range runs" 0 -- run --timeout 1e19 -- true

echo "== network"
expect_out "no network by default"     'Could not resolve|Failed to connect' -- run -- curl -sS -m 5 -o /dev/null https://example.com
expect_out "only loopback exists"      '^lo$' -- run -- python3 -c 'import socket; print(*[n for _, n in socket.if_nameindex()])'
if [ "${VSSR_TEST_OFFLINE:-}" != 1 ]; then
    expect "proxy allows listed hosts" 0   -- run --allow example.com -- curl -sS -m 15 -o /dev/null https://example.com
    expect_out "proxy blocks others"   '403' -- run --allow example.com -- curl -sS -m 15 -o /dev/null https://example.org
    expect_out "proxy blocks other ports" '403' -- run --allow example.com -- curl -sS -m 15 -o /dev/null https://example.com:8443
    expect_out "proxy blocks private addresses" 'blocked GET localhost:22' -- run --allow '*:*' -- curl -sS -m 5 -o /dev/null --noproxy '' -x http://127.0.0.1:3128 http://localhost:22/
    expect_out "no bypassing the proxy" 'Could not connect|Couldn.t resolve|Failed to connect' -- run --allow example.com -- curl -sS -m 5 --noproxy '*' https://93.184.215.14
    "$V" run --allow example.com --audit-log "$WORK/audit.jsonl" -- curl -sS -m 15 -o /dev/null https://example.com >/dev/null 2>&1
    grep -q '"action":"allow".*"host":"example.com"' "$WORK/audit.jsonl" && grep -q '"event":"exit"' "$WORK/audit.jsonl" \
        && ok "audit log records connections" || bad "audit log records connections"
    cat > hostnet.toml <<EOF
[fs]
rw = ["\$PWD"]
[net]
mode = "host"
tcp_connect = [443]
EOF
    expect "host mode: allowed port"   0   -- run -p hostnet.toml -- curl -sS -m 15 -o /dev/null https://example.com
    expect_out "host mode: other ports blocked by Landlock" 'Permission denied|Failed to connect|Could not connect' -- run -p hostnet.toml -- curl -sS -m 5 http://example.com
fi
# Landlock scoping: a host abstract unix socket is unreachable even with host networking.
python3 -c '
import socket,time,sys
s=socket.socket(socket.AF_UNIX); s.bind("\0vssr-test-abstract"); s.listen(); time.sleep(5)' &
lp=$!
sleep 0.3
cat > hostnet2.toml <<EOF
[fs]
rw = ["\$PWD"]
[net]
mode = "host"
EOF
expect_out "abstract sockets are scoped" 'Errno 1' -- run -p hostnet2.toml -- python3 -c 'import socket
s=socket.socket(socket.AF_UNIX)
try: s.connect("\0vssr-test-abstract"); print("connected")
except OSError as e: print(e)'
kill $lp 2>/dev/null

echo "== resource limits"
if "$V" check 2>/dev/null | grep -q '^ ok  resource limits'; then
    expect "memory limit kills hogs"   137 -- run --memory 64M -- python3 -c 'b = bytearray(512 << 20); b[::4096] = b"x" * (len(b) // 4096)'
    expect_out "pids limit holds"      'Resource temporarily unavailable|fork|retry' -- run --pids 16 -- sh -c 'for i in $(seq 40); do sleep 2 & done; wait'
    expect "limits allow normal work"  0   -- run --memory 256M --cpus 1 --pids 64 -- python3 -c 'print(sum(range(10**6)))'
else
    echo " --   skipped (no systemd user manager)"
fi

echo "== limits without systemd (fallbacks)"
# vssr with the user bus hidden, so no systemd scope can be created.
cat > "$WORK/nosd" <<EOF
#!/bin/sh
exec env -u DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR=/nonexistent "$V" "\$@"
EOF
chmod +x "$WORK/nosd"
REAL_V=$V V=$WORK/nosd
FORKS='import os, time
kids = []
while True:
    try: pid = os.fork()
    except OSError: break
    if pid == 0: time.sleep(30); os._exit(0)
    kids.append(pid)
print("forks", len(kids))'
AFFINITY='import os
n = len(os.sched_getaffinity(0))
try: os.sched_setaffinity(0, range(os.cpu_count())); w = "widened"
except PermissionError: w = "denied"
print(n, w)'
if "$V" run --pids 10 -- python3 -c "$FORKS" 2>&1 | grep -q pid_max; then
    echo " --   pids fallback skipped (no per-namespace pid_max)"
else
    expect_out "pids fallback: exact cap in the PID namespace" '^forks 8$' -- run --pids 10 -- python3 -c "$FORKS"
fi
expect     "memory limit refused without a cgroup (strict)"    125 -- run --memory 64M -- true
expect_out "memory limit skipped with --no-strict, and said"   'memory limit is not in effect' -- run --no-strict --memory 64M -- true
expect_out "cpus fallback pins, forced in strict mode"         '^1 denied$' -- run --cpus 1 -- python3 -c "$AFFINITY"
expect_out "cpus fallback pins plainly with --no-strict"       '^1 widened$' -- run --no-strict --cpus 1 -- python3 -c "$AFFINITY"
"$V" run --cpus 1 --pids 64 --audit-log "$WORK/limits.jsonl" -- true >/dev/null 2>&1
grep '"event":"start"' "$WORK/limits.jsonl" | grep -q '"cpus":{"forced":true,"pinned":\[[0-9]*\]}' \
    && grep '"event":"start"' "$WORK/limits.jsonl" | grep -Eq '"pids":"(pid-namespace|none)"' \
    && ok "the start event says how limits apply" || bad "the start event says how limits apply" "$(cat "$WORK/limits.jsonl" 2>/dev/null)"
V=$REAL_V
cat > pin.toml <<EOF
[fs]
rw = ["\$PWD"]
[limits]
cpu_method = "pin"
cpu_choice = [0]
EOF
expect_out "cpu_method = \"pin\" pins even with systemd"     '^1 widened$' -- run -p pin.toml --cpus 1 -- python3 -c "$AFFINITY"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
