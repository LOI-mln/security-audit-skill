#!/usr/bin/env bash
# sandbox-run.sh - run one command inside a locked-down container, or refuse.
#
# Reference launcher for the controls in SKILL.md "Universal execution safety":
#   network      --network none; the container keeps only its own loopback
#   environment  the runtime is started through `env -i`; the container gets
#                the fixed HOME/TMPDIR/XDG_CACHE_HOME, the --env pairs, and the
#                runtime's PATH/HOSTNAME; variables baked into the image are cleared
#   filesystem   read-only root, target read-only at /target, scratch
#                read-write at /scratch, size-limited tmpfs at /tmp
#   privileges   invoking uid:gid, no capabilities, no-new-privileges
#   limits       cpu, memory without swap, pids, file size, open files, and a
#                wall-clock timeout enforced from outside the container
#
# Exit status: the command's own status, or
#   2        usage error or refused argument
#   3        sandbox unavailable (no runtime, daemon unreachable, image not
#            local); the caller records this as a needs_validation blocker
#   124      wall-clock timeout, container killed
#   125-127  set by the runtime when it cannot start the command
# Requires bash 3.2 or later.

set -u
LC_ALL=C
export LC_ALL

PROG=sandbox-run
SELF=$0

usage() {
  cat <<'EOF'
Usage:
  sandbox-run.sh --image <local-image> --target <abs dir> --scratch <abs dir>
                 [--env NAME=VALUE]... [--loopback] [--cpus N] [--memory SIZE]
                 [--pids N] [--fsize-mb N] [--timeout SECONDS] [--tmpfs-mb N]
                 [--workdir PATH] -- <command> [args...]
  sandbox-run.sh --self-test --image <local-image> --scratch <abs dir>

Runs one command in a container, or refuses. The image must already be local;
nothing is ever pulled. Inside the container:
  /target   the --target directory, read-only
  /scratch  the --scratch directory, read-write, and the default --workdir
  /tmp      a size-limited tmpfs; every other path is read-only
  network   none. The container still has its own private loopback interface,
            so --loopback changes nothing: it only lets a caller state that the
            check needs local client/server traffic.
  env       HOME=/scratch/home TMPDIR=/scratch/tmp XDG_CACHE_HOME=/scratch/cache,
            the --env pairs, and the runtime's PATH and HOSTNAME. The host
            environment is never inherited and variables baked into the image
            are cleared: pass --env for any the toolchain needs.
  identity  the invoking uid:gid, no capabilities, no-new-privileges. The image
            entrypoint is cleared so exactly <command> runs. stdin is not forwarded.
  limits    --cpus 1, --memory 1g (no swap), --pids 256, --fsize-mb 64,
            --tmpfs-mb 64, 1024 open files, and --timeout 120 seconds of wall
            clock enforced from outside the container.

Refused: a target or scratch that is relative, missing, or a symlink; scratch
inside target or target inside scratch; scratch that is /, /tmp, or the home
directory; a target or scratch that contains the home directory.

Runtime: docker, or podman when docker is absent. SANDBOX_RUNTIME overrides.

--self-test runs canary commands against an empty temporary target and prints
SELF-TEST PASS or SELF-TEST FAIL: <checks>, exiting 0 or 1.

Exit status: the command's status, or 2 for a usage error or refused argument,
3 when the sandbox is unavailable (record a needs_validation blocker), 124 on
timeout.
EOF
}

say() { printf '%s: %s\n' "$PROG" "$*" >&2; }
refuse() {
  say "refused: $*"
  exit 2
}
blocker() {
  say "sandbox unavailable: $*"
  say "do not execute target code; record this as a needs_validation blocker"
  exit 3
}
# Caller-supplied text is printed only after unprintable bytes are replaced.
printable() { printf '%s' "$1" | tr -c '[:print:]' '?'; }
has_control() {
  case "$1" in *[[:cntrl:]]*) return 0 ;; esac
  return 1
}
# A positive decimal integer of at most nine digits, without a leading zero.
is_count() {
  case "$1" in '' | 0* | *[!0-9]*) return 1 ;; esac
  [ "${#1}" -le 9 ]
}
valid_env_name() { [[ $1 =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; }
# True when physical path $1 equals or lies inside physical path $2.
is_within() {
  [ "$1" = "$2" ] && return 0
  [ "$2" = / ] && return 0
  case "$1" in "$2"/*) return 0 ;; esac
  return 1
}
# Validate a host directory argument and set $resolved to its physical path.
resolve_dir() {
  local label=$1 dir=$2
  case "$dir" in /*) ;; *) refuse "--$label must be an absolute path" ;; esac
  while [ "$dir" != / ] && [ "${dir%/}" != "$dir" ]; do dir=${dir%/}; done
  [ -L "$dir" ] && refuse "--$label must not be a symlink"
  [ -d "$dir" ] || refuse "--$label is not an existing directory"
  resolved=$(cd -P -- "$dir" 2>/dev/null && pwd -P) || refuse "--$label cannot be resolved"
  has_control "$resolved" && refuse "--$label must not contain control characters"
  # The path is passed in --mount, whose fields are comma-separated and may be quoted.
  case "$resolved" in *[,\"]*) refuse "--$label must not contain a comma or double quote" ;; esac
}

# ---- arguments -------------------------------------------------------------

image='' target='' scratch='' workdir=/scratch
cpus=1 memory=1g pids=256 fsize_mb=64 timeout=120 tmpfs_mb=64
self_test=0
env_names='HOME TMPDIR XDG_CACHE_HOME'
env_args=(--env HOME=/scratch/home --env TMPDIR=/scratch/tmp --env XDG_CACHE_HOME=/scratch/cache)

while [ $# -gt 0 ]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --self-test)
      self_test=1
      shift
      continue
      ;;
    --loopback) # accepted to state intent only; see usage
      shift
      continue
      ;;
    --)
      shift
      break
      ;;
    --image | --target | --scratch | --env | --cpus | --memory | --pids | --fsize-mb | --timeout | --tmpfs-mb | --workdir) ;;
    *) refuse "unknown argument '$(printable "$1")'; the command goes after --" ;;
  esac
  [ $# -ge 2 ] || refuse "$1 requires a value"
  case "$1" in
    --image) image=$2 ;;
    --target) target=$2 ;;
    --scratch) scratch=$2 ;;
    --workdir) workdir=$2 ;;
    --env)
      case "$2" in *=*) ;; *) refuse "--env takes NAME=VALUE" ;; esac
      env_name=${2%%=*}
      valid_env_name "$env_name" || refuse "--env name must match ^[A-Za-z_][A-Za-z0-9_]*\$"
      case " $env_names " in
        *" $env_name "*) refuse "--env $env_name is fixed by the sandbox or was given twice" ;;
      esac
      env_names="$env_names $env_name"
      env_args+=(--env "$2")
      ;;
    --cpus) # zero would mean "unlimited" to the runtime
      [[ $2 =~ ^[0-9]{1,4}(\.[0-9]{1,3})?$ ]] && ! [[ $2 =~ ^0*(\.0*)?$ ]] ||
        refuse "--cpus must be a positive number"
      cpus=$2
      ;;
    --memory)
      [[ $2 =~ ^[1-9][0-9]{0,11}[bkmgBKMG]?$ ]] || refuse "--memory must be a positive size such as 512m or 1g"
      memory=$2
      ;;
    --pids)
      is_count "$2" || refuse "--pids must be a positive integer"
      pids=$2
      ;;
    --fsize-mb)
      is_count "$2" || refuse "--fsize-mb must be a positive integer"
      fsize_mb=$2
      ;;
    --timeout)
      is_count "$2" || refuse "--timeout must be a positive integer number of seconds"
      timeout=$2
      ;;
    --tmpfs-mb)
      is_count "$2" || refuse "--tmpfs-mb must be a positive integer"
      tmpfs_mb=$2
      ;;
  esac
  shift 2
done

[ -n "$image" ] || refuse "--image is required"
[[ $image =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*$ ]] || refuse "--image is not a plain image reference"
case "$workdir" in /*) ;; *) refuse "--workdir must be an absolute path inside the container" ;; esac
has_control "$workdir" && refuse "--workdir must not contain control characters"

home_real=''
if [ -n "${HOME:-}" ] && [ -d "$HOME" ]; then
  home_real=$(cd -P -- "$HOME" 2>/dev/null && pwd -P) || home_real=''
fi
tmp_real=$(cd -P /tmp 2>/dev/null && pwd -P) || tmp_real=/tmp

[ -n "$scratch" ] || refuse "--scratch is required"
resolve_dir scratch "$scratch"
scratch_real=$resolved
[ "$scratch_real" = / ] && refuse "--scratch must not be /"
[ "$scratch_real" = "$tmp_real" ] && refuse "--scratch must not be /tmp itself"
if [ -n "$home_real" ] && is_within "$home_real" "$scratch_real"; then
  refuse "--scratch must not be the home directory or contain it"
fi

if [ "$self_test" = 1 ]; then
  [ -z "$target" ] && [ $# -eq 0 ] ||
    refuse "--self-test takes --image and --scratch only; it creates its own empty target"
else
  [ -n "$target" ] || refuse "--target is required"
  [ $# -gt 0 ] || refuse "a command is required after --"
  resolve_dir target "$target"
  target_real=$resolved
  is_within "$scratch_real" "$target_real" && refuse "--scratch must not be the target or inside it"
  is_within "$target_real" "$scratch_real" && refuse "--target must not be inside --scratch"
  if [ -n "$home_real" ] && is_within "$home_real" "$target_real"; then
    refuse "--target must not be the home directory or contain it"
  fi
fi

# ---- runtime ---------------------------------------------------------------

if [ -n "${SANDBOX_RUNTIME:-}" ]; then
  runtime=$(command -v -- "$SANDBOX_RUNTIME" 2>/dev/null) ||
    blocker "SANDBOX_RUNTIME '$(printable "$SANDBOX_RUNTIME")' was not found or is not executable"
elif runtime=$(command -v docker 2>/dev/null); then
  :
elif runtime=$(command -v podman 2>/dev/null); then
  :
else
  blocker "no container runtime found; install docker or podman, or set SANDBOX_RUNTIME"
fi
case "$runtime" in */*) ;; *) blocker "the container runtime must resolve to an executable file" ;; esac
case "${runtime##*/}" in podman*) runtime_kind=podman ;; *) runtime_kind=docker ;; esac

# The runtime client sees only these variables, so its configuration cannot
# expand anything else from the host environment into the container.
client_env=("PATH=${PATH:-/usr/bin:/bin}")
client_env_names=' PATH '
for client_var in HOME DOCKER_HOST DOCKER_CONFIG XDG_RUNTIME_DIR; do
  if [ -n "${!client_var:-}" ]; then
    client_env+=("$client_var=${!client_var}")
    client_env_names="$client_env_names$client_var "
  fi
done
runtime_cmd() { /usr/bin/env -i "${client_env[@]}" "$runtime" "$@"; }

# One inspect both proves the image is local and lists the variables it bakes in.
image_env=$(runtime_cmd image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$image" 2>/dev/null) || {
  if runtime_cmd version >/dev/null 2>&1; then
    blocker "image '$image' is not present locally and this launcher never pulls"
  fi
  blocker "'$(printable "$runtime")' is not responding; is the daemon running?"
}

# ---- self-test -------------------------------------------------------------

selftest_dir=''
failures=''
fail() { failures="${failures:+$failures; }$1"; }

# Runs under `sh -c` inside the sandbox; uses only sh builtins and optional probes.
IFS= read -r -d '' CANARY <<'EOF' || true
nonce=$1
for entry in /sys/class/net/*; do
  [ -d "$entry" ] || continue
  flags=unreadable
  if [ -r "$entry/flags" ]; then read -r flags < "$entry/flags" || :; fi
  echo "IFACE ${entry##*/} $flags"
done
probe() {
  tool=$1
  shift
  command -v "$tool" >/dev/null 2>&1 || return 0
  if "$@" </dev/null >/dev/null 2>&1; then echo "PROBE $tool open"; else echo "PROBE $tool blocked"; fi
}
probe getent getent hosts example.com
probe wget wget -q -T 5 -O /dev/null http://example.com/
probe curl curl -s -m 5 -o /dev/null http://example.com/
probe nc nc -w 5 example.com 80
if ( : > /target/.sandbox-run-selftest ) 2>/dev/null; then echo "TARGET_WRITE allowed"; else echo "TARGET_WRITE denied"; fi
if ( echo "$nonce" > "/scratch/.sandbox-run-selftest.$nonce" ) 2>/dev/null; then echo "SCRATCH_WRITE ok"; else echo "SCRATCH_WRITE failed"; fi
EOF

run_self_test() {
  local tmp_base=${TMPDIR:-/tmp} nonce="$$-$RANDOM-$RANDOM" out status line name flags marker
  local seen_fixed=0 unexpected='' net_evidence=0 net_open='' target_denied=0 scratch_ok=0
  selftest_dir=$(mktemp -d "${tmp_base%/}/sandbox-run-selftest.XXXXXX") || {
    echo "SELF-TEST FAIL: cannot create an empty temporary target"
    exit 1
  }

  # Check 4: `env` runs directly (no shell), so its output is exactly the
  # environment the runtime handed to the command. The canary variable is in
  # this launcher's own environment and must not arrive.
  out=$(SANDBOX_RUN_SELFTEST_CANARY=host-value "$BASH" "$SELF" --image "$image" \
    --target "$selftest_dir" --scratch "$scratch_real" --timeout 60 -- env)
  status=$?
  if [ "$status" -ne 0 ]; then
    fail "environment: canary did not run (exit $status)"
  else
    while IFS= read -r line; do
      case "$line" in
        HOME=/scratch/home | TMPDIR=/scratch/tmp | XDG_CACHE_HOME=/scratch/cache) seen_fixed=$((seen_fixed + 1)) ;;
        PATH=* | HOSTNAME=*) ;;  # added by the runtime
        container=*) ;;          # constant marker added by podman
        '') ;;
        *) unexpected="$unexpected $(printable "${line%%=*}")" ;;
      esac
    done <<EOF
$out
EOF
    [ -z "$unexpected" ] || fail "environment: unexpected variable(s):$unexpected"
    [ "$seen_fixed" -eq 3 ] || fail "environment: fixed HOME/TMPDIR/XDG_CACHE_HOME not all present"
  fi

  # Checks 1-3: network, read-only target, writable scratch.
  out=$("$BASH" "$SELF" --image "$image" --target "$selftest_dir" --scratch "$scratch_real" \
    --timeout 60 -- sh -c "$CANARY" sh "$nonce")
  status=$?
  marker=$scratch_real/.sandbox-run-selftest.$nonce
  if [ "$status" -ne 0 ]; then
    fail "network/target/scratch: canary did not run (exit $status)"
  else
    while IFS= read -r line; do
      case "$line" in
        'IFACE lo '*) net_evidence=1 ;;
        'IFACE '*)
          # Some kernels create fallback tunnel devices in every namespace. A
          # device that is administratively down (IFF_UP clear) carries nothing
          # and cannot be raised without CAP_NET_ADMIN; anything else fails.
          name=${line#IFACE }
          flags=${name#* }
          name=${name%% *}
          case "$flags" in
            0x*[02468aceACE]) ;;
            *) net_open="$net_open interface $(printable "$name") is up or unreadable;" ;;
          esac
          ;;
        'PROBE '*' open') net_open="$net_open ${line#PROBE } (outbound probe succeeded);" ;;
        'PROBE '*' blocked') net_evidence=1 ;;
        'TARGET_WRITE denied') target_denied=1 ;;
        'SCRATCH_WRITE ok') scratch_ok=1 ;;
      esac
    done <<EOF
$out
EOF
    if [ -n "$net_open" ]; then
      fail "network:$net_open"
    elif [ "$net_evidence" -ne 1 ]; then
      fail "network: isolation could not be verified (no probe tool and no /sys/class/net)"
    fi
    if [ "$target_denied" -ne 1 ] || [ -e "$selftest_dir/.sandbox-run-selftest" ]; then
      fail "target: a write under /target succeeded"
    fi
    if [ "$scratch_ok" -ne 1 ] || [ ! -f "$marker" ] || [ -L "$marker" ] ||
      [ "$(cat "$marker" 2>/dev/null)" != "$nonce" ]; then
      fail "scratch: a write under /scratch did not reach the scratch directory"
    fi
  fi
  rm -f -- "$marker"

  if [ -n "$failures" ]; then
    echo "SELF-TEST FAIL: $failures"
    exit 1
  fi
  echo "SELF-TEST PASS"
  exit 0
}

# ---- cleanup, timeout ------------------------------------------------------

container='' run_pid='' watchdog_pid='' nap_pid=''

# Prints the container name when one existed and is now killed and removed.
remove_container() { runtime_cmd rm -f "$container" 2>/dev/null; }

cleanup() {
  trap - EXIT HUP INT TERM
  [ -n "$watchdog_pid" ] && kill "$watchdog_pid" 2>/dev/null
  if [ -n "$container" ]; then
    if [ -n "$run_pid" ]; then
      # Interrupted mid-run. The client is still our unreaped child: stop it so
      # it cannot start the container late, then remove the container by name.
      kill -KILL "$run_pid" 2>/dev/null
      wait "$run_pid" 2>/dev/null
      if [ -z "$(remove_container)" ]; then
        sleep 1 # a create request may still have been in flight
        remove_container >/dev/null
      fi
    else
      remove_container >/dev/null
    fi
  fi
  [ -n "$selftest_dir" ] && rm -rf -- "$selftest_dir"
  return 0
}
trap cleanup EXIT
trap 'cleanup; exit 129' HUP
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# Background subshell. Exits 1 once the timeout has expired, 0 if cancelled first.
watchdog() {
  local expired=0 tries=0
  trap - EXIT HUP INT
  trap '[ -n "$nap_pid" ] && kill "$nap_pid" 2>/dev/null; exit "$expired"' TERM
  sleep "$timeout" &
  nap_pid=$!
  wait "$nap_pid"
  expired=1
  # Kill by name. Retry briefly in case the container had not been created yet.
  while [ "$tries" -lt 5 ] && [ -z "$(remove_container)" ]; do
    sleep 1 &
    nap_pid=$!
    wait "$nap_pid"
    tries=$((tries + 1))
  done
  # Nothing was removable and the launcher is still waiting: the client is
  # stuck, so stop it rather than let it outlive the wall-clock limit.
  if [ "$tries" -ge 5 ] && kill -0 "$$" 2>/dev/null; then kill -KILL "$run_pid" 2>/dev/null; fi
  exit 1
}

[ "$self_test" = 1 ] && run_self_test

# ---- launch ----------------------------------------------------------------

uid_gid="$(id -u):$(id -g)"
fsize_bytes=$((fsize_mb * 1048576))
container_name="sandbox-run-$$-$(date +%s)-$RANDOM"
run_args=(run --rm --name "$container_name" --pull=never
  --network none
  --read-only
  --mount "type=bind,source=$target_real,target=/target,readonly"
  --mount "type=bind,source=$scratch_real,target=/scratch"
  --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=${tmpfs_mb}m,mode=1777"
  --workdir "$workdir"
  --user "$uid_gid" --cap-drop ALL --security-opt no-new-privileges
  --cpus "$cpus" --memory "$memory" --memory-swap "$memory" --pids-limit "$pids"
  --ulimit "fsize=$fsize_bytes:$fsize_bytes" --ulimit nofile=1024:1024
  --entrypoint ''
  "${env_args[@]}")
# Rootless podman maps the invoking user into the container only on request.
if [ "$runtime_kind" = podman ] && [ "$(id -u)" -ne 0 ]; then run_args+=(--userns=keep-id); fi

# Clear every variable the image bakes in, except PATH and names set above.
cleared=''
while IFS= read -r line; do
  image_var=${line%%=*}
  [ "$image_var" != "$line" ] || continue # no '=': not the start of a variable
  case "$image_var" in '' | *[[:space:][:cntrl:]]*) continue ;; esac
  case " $env_names PATH $cleared " in *" $image_var "*) continue ;; esac
  if [ "$runtime_kind" = podman ]; then
    run_args+=(--unsetenv "$image_var")
  else
    # A bare `--env NAME` removes the image's value, but it would copy NAME from
    # the client's environment if it were set there, so refuse that case.
    case "$client_env_names" in
      *" $image_var "*) refuse "the image sets $image_var, which cannot be cleared safely; pass --env $image_var=VALUE" ;;
    esac
    run_args+=(--env "$image_var")
  fi
  cleared="$cleared $image_var"
done <<EOF
$image_env
EOF

# Scratch-local HOME, TMPDIR, and cache. mkdir never follows a symlink here.
for sub in home tmp cache; do
  [ -L "$scratch_real/$sub" ] && refuse "$sub in the scratch directory must not be a symlink"
  [ -d "$scratch_real/$sub" ] || mkdir -m 700 -- "$scratch_real/$sub" 2>/dev/null ||
    refuse "cannot create $sub in the scratch directory"
done

cleared=${cleared# }
say "runtime=$runtime image=$image network=none(own-loopback-only) rootfs=read-only" \
  "target=$target_real:ro scratch=$scratch_real:rw tmpfs_mb=$tmpfs_mb workdir=$workdir" \
  "user=$uid_gid caps=none no_new_privileges=on cpus=$cpus memory=$memory swap=off pids=$pids" \
  "fsize_mb=$fsize_mb nofile=1024 timeout_s=$timeout env=${env_names// /,}" \
  "image_env_cleared=${cleared// /,} container=$container_name"

container=$container_name
/usr/bin/env -i "${client_env[@]}" "$runtime" "${run_args[@]}" "$image" "$@" </dev/null &
run_pid=$!
watchdog </dev/null >/dev/null 2>&1 &
watchdog_pid=$!

wait "$run_pid" 2>/dev/null # the redirect only hides bash's own "Killed" job notice
status=$?
run_pid=''
kill "$watchdog_pid" 2>/dev/null
wait "$watchdog_pid" 2>/dev/null
expired=$?
watchdog_pid=''
if [ "$expired" -eq 1 ]; then
  say "timed out after ${timeout}s; container killed"
  exit 124
fi
exit "$status"
