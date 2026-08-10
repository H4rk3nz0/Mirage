#!/bin/bash
# Stop processes this project started. By PID. Never by pattern.
#
#   scripts/stop.sh <pidfile|run-dir> [...]
#
# WHY THIS EXISTS, and why it is the ONLY sanctioned way to stop things here.
#
# `pkill -f mirage-client` matches any process whose command line merely CONTAINS
# that string - a wrapper script, an editor with the file open, a shell that ran
# sha256sum on the binary. It is not a filter, it is a substring search over every
# process on the machine, and the harness is frequently the longest such match.
#
# This is not a hypothetical. In this repository's own tooling it has killed the
# invoking shell four separate times: `pkill -f mirage-client` in the capture
# harness, `pkill -f "Xvfb :99"` in a test wrapper, and `pkill -f
# browser_capture.py` twice. Each time the comment explaining the hazard had
# already been written, in this repo, by the person who then reached for it again.
#
# Knowing the rule does not prevent the reach. Removing the affordance does. So
# there is one stop path, it takes PIDs, and it is this file. If you find yourself
# typing `pkill -f` while working on Mirage, use this instead.
#
# Escalates: TERM, wait, then KILL. A signal sent is not a process gone -
# `kill -INT` on an asyncio server is not promptly honoured, which left a relay
# holding its port into the next run and made a capture measure nothing.
# AND IT OWNS DISCOVERY TOO, which is the mistake that made a fifth incident.
#
# The first version of this file removed `pkill`. It did not remove `pgrep`, so
# the very next task reached for `pgrep -f "firefox.*ffprofile"` to FIND a process
# and killed the result - and the pgrep matched its own shell, because the shell's
# command line contains the pattern. An affordance fix has to cover the whole
# gesture, not the step you happened to be thinking about while writing it.
#
#   stop.sh --list <run-dir>        what is tracked, and is it alive
#   stop.sh --find <exact-string>   REPORT ONLY. Never kills. Exact substring
#                                   match over /proc/<pid>/cmdline, and it
#                                   excludes its own process tree, so it cannot
#                                   report itself the way pgrep does.
set -uo pipefail

self_tree() {
  # pids to never report or touch: this script, its parent, its children.
  echo "$$"; echo "$PPID"
  ps -o pid= --ppid "$$" 2>/dev/null
}

if [ "${1:-}" = "--find" ]; then
  needle="${2:?--find needs an exact substring, e.g. an absolute path}"
  case "$needle" in
    *[!A-Za-z0-9/._-]*)
      echo "refusing: --find takes a literal string, not a pattern." >&2
      echo "  Patterns are how pkill/pgrep match the caller's own shell." >&2
      exit 2 ;;
  esac
  mine=" $(self_tree | tr '\n' ' ') "
  hits=0
  for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    case "$mine" in *" $p "*) continue ;; esac
    # 2>/dev/null on the redirect too: a process can exit between the
    # listing and the read, and that race is not a finding.
    cl=$( { tr '\0' ' ' < "/proc/$p/cmdline"; } 2>/dev/null ) || continue
    case "$cl" in
      *"$needle"*)
        echo "  pid=$p  $(echo "$cl" | cut -c1-110)"; hits=$((hits+1)) ;;
    esac
  done
  [ "$hits" -eq 0 ] && echo "  no process matches (excluding this script's own tree)"
  echo
  echo "REPORT ONLY - nothing was stopped. To stop something, record a pidfile"
  echo "and pass it to this script. If it has no pidfile, it was started wrong."
  exit 0
fi

if [ "${1:-}" = "--list" ]; then
  d="${2:?--list needs a run directory}"
  shopt -s nullglob
  for f in "$d"/*.pid; do
    pid=$(cat "$f" 2>/dev/null)
    if kill -0 "$pid" 2>/dev/null; then echo "  alive $pid  ($(basename "$f"))"
    else echo "  dead  $pid  ($(basename "$f"))"; fi
  done
  shopt -u nullglob
  exit 0
fi

[ $# -ge 1 ] || { sed -n '2,4p' "$0"; exit 2; }

reap() {
  local pid="$1" i
  [ -n "$pid" ] || return 0
  kill -0 "$pid" 2>/dev/null || return 0
  kill -TERM "$pid" 2>/dev/null || return 0
  for i in $(seq 1 30); do
    kill -0 "$pid" 2>/dev/null || { echo "  stopped $pid"; return 0; }
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null
  for i in $(seq 1 10); do
    kill -0 "$pid" 2>/dev/null || { echo "  killed  $pid"; return 0; }
    sleep 0.2
  done
  echo "  WOULD NOT DIE: $pid"
  return 1
}

rc=0
for arg in "$@"; do
  if [ -d "$arg" ]; then
    # A run directory: stop everything it recorded a pid for.
    shopt -s nullglob
    files=("$arg"/*.pid)
    shopt -u nullglob
    if [ ${#files[@]} -eq 0 ]; then
      echo "$arg: no .pid files - nothing recorded, nothing to stop"
      continue
    fi
    echo "$arg:"
    for f in "${files[@]}"; do
      reap "$(cat "$f" 2>/dev/null)" || rc=1
      rm -f "$f"
    done
  elif [ -f "$arg" ]; then
    echo "$arg:"
    reap "$(cat "$arg" 2>/dev/null)" || rc=1
    rm -f "$arg"
  else
    echo "$arg: not a pidfile or run directory"
    rc=1
  fi
done
exit "$rc"
