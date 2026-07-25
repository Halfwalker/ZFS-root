#!/bin/bash
# Manual Goss Testing Script for ZFS-root
# Run this in a terminal with sudo access
#
# Usage: ./test-goss-manual.sh [options] [build-dir]
#
# Options:
#   --variant VARIANT         Encryption variant: NOENC, ZFSENC, LUKS (auto-detected if not set)
#   --pool-name NAME          ZFS pool name (auto-detected from build-metadata.txt or dir name)
#   --suite NAME              Ubuntu suite name, e.g. noble (auto-detected)
#   --ssh-port PORT           SSH port for main OS (default: 2222)
#   --dropbear-port PORT      SSH port for Dropbear unlock (default: 1222)
#   --save-results true|false Save goss output to build dir (default: true)
#   --help, -h                Show this help
#
# Local testing in container (from ZFS-root repo root)
# docker run --rm -it -v "$(pwd)":"${PWD}" -w "${PWD}" -v /qemu/builds:/qemu/builds -v /usr/share/OVMF:/usr/share/OVMF:ro --device /dev/kvm --name hashi --entrypoint=/bin/sh hashicorp/packer:light
# Then run steps from .gitea/workflows/packer-validate.yml or packer-build.yml

set -e

usage() {
    cat <<EOF
Usage: $0 [options] [build-dir]

Options:
  --variant VARIANT         Encryption variant: NOENC, ZFSENC, LUKS (auto-detected if not set)
  --pool-name NAME          ZFS pool name (auto-detected from build-metadata.txt or dir name)
  --suite NAME              Ubuntu suite name, e.g. noble (auto-detected)
  --ssh-port PORT           SSH port for main OS (default: 2222)
  --dropbear-port PORT      SSH port for Dropbear unlock (default: 1222)
  --save-results true|false Save goss output to build dir (default: true)
  --help, -h                Show this help

If build-dir is not provided, fzf is used to select one interactively.

Auto-detection reads build-metadata.txt from the build directory if present.
Directory name is used as fallback: packer-<suite>-<VARIANT>-<date>
EOF
}

# Defaults
SSH_PORT=2222
DROPBEAR_PORT=1222
SAVE_RESULTS=true
VARIANT=""
POOL_NAME=""
SUITE_NAME=""
BUILD_DIR=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        --variant)
            VARIANT="$2"
            shift 2
            ;;
        --pool-name)
            POOL_NAME="$2"
            shift 2
            ;;
        --suite)
            SUITE_NAME="$2"
            shift 2
            ;;
        --ssh-port)
            SSH_PORT="$2"
            shift 2
            ;;
        --dropbear-port)
            DROPBEAR_PORT="$2"
            shift 2
            ;;
        --save-results)
            SAVE_RESULTS="$2"
            shift 2
            ;;
        -*)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            # Positional argument: build dir
            BUILD_DIR="$1"
            shift
            ;;
    esac
done

# If no build dir provided, prompt
if [[ -z "$BUILD_DIR" ]]; then
    echo "Must provide a path to a packer build dir"
    if command -v fzf >/dev/null 2>&1; then
        echo "Pick one to boot or ESC to exit"
        BUILD_DIR=$(find /qemu/builds/* -type d | fzf --height 20% --border --reverse --margin=5%,40%,0%,5%)
    else
        echo "For example, from here"
        find /qemu/builds/* -type d | xargs -I {} echo "$0 {}"
    fi
fi
[[ -z "$BUILD_DIR" ]] && exit 1

# Strip trailing slash
BUILD_DIR="${BUILD_DIR%/}"

# Auto-detect from build-metadata.txt (takes priority over dir name)
if [[ -f "${BUILD_DIR}/build-metadata.txt" ]]; then
    while IFS='=' read -r key value; do
        case "$key" in
            DISCENC)     [[ -z "$VARIANT"   ]] && VARIANT="$value" ;;
            UBUNTU_NAME) [[ -z "$SUITE_NAME" ]] && SUITE_NAME="$value" ;;
        esac
    done < "${BUILD_DIR}/build-metadata.txt"
fi

# Fallback: auto-detect from build directory name
# Pattern: packer-<suite>-<VARIANT>-<date>
# e.g.     packer-noble-NOENC-2026-02-10-0247
DIRNAME=$(basename "$BUILD_DIR")
if [[ "$DIRNAME" =~ ^packer-([a-z]+)-([A-Za-z0-9]+)- ]]; then
    [[ -z "$SUITE_NAME" ]] && SUITE_NAME="${BASH_REMATCH[1]}"
    [[ -z "$VARIANT"    ]] && VARIANT="${BASH_REMATCH[2]}"
fi

# Final fallback defaults
: "${VARIANT:=NOENC}"
: "${SUITE_NAME:=noble}"
# Pool name defaults to suite name if not explicitly provided
: "${POOL_NAME:=$SUITE_NAME}"

# SCRIPT_DIR is where we look for the packer-validation/ directory to scp to the VM.
# We resolve the project root (one level up from this script's directory) so that
# run-kvm.sh can be found at ./run-kvm.sh regardless of the caller's working directory.
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o pubkeyauthentication=no"
DROPBEAR_OPTS="-i packer-validation/CICD_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
MAIN_USER="packer"

test_ssh() {
    local PORT=$1
    local STEP=$2

    echo "[${STEP}/6] Waiting for SSH (up to 180s)..."
    TIMEOUT=180
    ELAPSED=0
    while true; do
        # Try to read the SSH banner - this proves SSH is actually running
        if BANNER=$(timeout 2 nc -C localhost $PORT 2>/dev/null | head -1 | tr -d '\r'); then
            if [[ "$BANNER" == SSH-* ]]; then
                echo "  SSH banner received: $BANNER"
                break
            fi
        fi

        if ! kill -0 $VM_PID 2>/dev/null; then
            echo "ERROR: VM died during boot"
            exit 1
        fi
        sleep 5
        ELAPSED=$((ELAPSED + 5))
        if [[ $ELAPSED -ge $TIMEOUT ]]; then
            echo "ERROR: SSH timeout after ${TIMEOUT}s"
            kill $VM_PID 2>/dev/null || true
            exit 1
        fi
        echo "  ... waiting ($ELAPSED/${TIMEOUT}s)"
    done
    echo "  SSH ready!"
}

echo "=== ZFS-root Goss Testing ==="
echo "Build:    $BUILD_DIR"
echo "Variant:  $VARIANT"
echo "Suite:    $SUITE_NAME"
echo "Pool:     $POOL_NAME"
echo "SSH port: $SSH_PORT"
[[ "$VARIANT" != "NOENC" ]] && echo "Dropbear: $DROPBEAR_PORT"
echo ""

# Step 1: Fix permissions if needed
if [[ ! -r "${BUILD_DIR}/efivars.fd" ]]; then
    echo "[1/6] Fixing efivars.fd permissions..."
    sudo chmod 644 "${BUILD_DIR}/efivars.fd"
else
    echo "[1/6] efivars.fd permissions OK"
fi

# Step 2: Boot VM
echo "[2/6] Booting VM..."
cd "$SCRIPT_DIR"

if [[ "$VARIANT" == "NOENC" ]]; then
    ./run-kvm.sh --ssh $SSH_PORT "$BUILD_DIR"
else
    ./run-kvm.sh --ssh $SSH_PORT --dropbear $DROPBEAR_PORT "$BUILD_DIR"
fi

# Wait a moment for QEMU to start
sleep 3

# Get the QEMU PID from the file run-kvm.sh writes
if [[ -f /tmp/qemu-vm.pid ]]; then
    VM_PID=$(cat /tmp/qemu-vm.pid)
else
    echo "ERROR: Could not find QEMU PID file"
    exit 1
fi

if [[ -z "$VM_PID" ]] || ! kill -0 "$VM_PID" 2>/dev/null; then
    echo "ERROR: QEMU process not running"
    exit 1
fi
echo "  QEMU running with PID: $VM_PID"

# Step 3: Wait for SSH
# For NOENC: wait directly for OpenSSH on SSH_PORT
# For ZFSENC/LUKS: wait for Dropbear, unlock ZFS, then wait for OpenSSH
if [[ "$VARIANT" == "NOENC" ]]; then
    test_ssh ${SSH_PORT} 3
    # Give system a moment to fully initialize after SSH starts
    sleep 5
else
    # Step 3a: Wait for Dropbear (ZFSBootMenu unlock SSH)
    test_ssh ${DROPBEAR_PORT} 3a
    # Give system a moment to fully initialize after SSH starts
    sleep 5

    # Unlock disk encryption via Dropbear SSH, then kexec into the main OS.
    # The SSH command is run in the background; we kill it after the main OS comes up.
    #
    # IMPORTANT: Quoting rules for the remote command (do not alter without testing):
    #   echo 'password' | load_key POOL/ROOT/SUITE    password in single quotes, dataset NO quotes
    #   find_be_kernels POOL/ROOT/SUITE               dataset NO quotes
    #   kexec_kernel "$(select_kernel POOL/ROOT/SUITE)"  subshell inside double-quotes, dataset NO quotes
    #
    # We build the dataset path into a variable first, then embed it using
    # quote-breaking around the single-quoted remote command string.
    # The \$( before select_kernel is intentional: prevents local expansion,
    # so the remote shell performs the subshell substitution.
    DATASET="${POOL_NAME}/ROOT/${SUITE_NAME}"

    # Per-variant unlock differences. Everything else (find_be_kernels + kexec_kernel)
    # is identical for both.
    #
    #   ZFSENC: load_key is a ZBM builtin that decrypts an already-imported pool. The
    #           pool was imported readonly by ZBM's own init.d during startup, so no
    #           separate import_pool call is needed. Fast — 2s is enough for
    #           find_be_kernels to see the kernels file populate.
    #
    #   LUKS:   Two-step chicken-and-egg: the pool can't be imported until the LUKS
    #           partition is unlocked, so ZBM's init.d cannot pre-import it.
    #             1. luks-unlock.sh (agorgl/zbm-luks-unlock hook) does cryptsetup
    #                luksOpen, reads password from stdin.
    #             2. import_pool ${POOL} — ZBM's own wrapper: -N -o readonly=on.
    #                Plain `zpool import` would auto-mount datasets (mountpoint=/ on
    #                the root BE), which then collides with mount_zfs inside
    #                kexec_kernel. Must use import_pool.
    #           Both steps are synchronous, but keep a 10s buffer for slower storage.
    #           luks-unlock.sh renames itself to .completed after success — safe to
    #           call again idempotently on a fresh boot, but not after ZBM's early-
    #           setup phase has already run it.
    case "$VARIANT" in
        ZFSENC)
            UNLOCK_STEP="load_key ${DATASET}"
            POST_UNLOCK_WAIT=2
            ;;
        LUKS)
            UNLOCK_STEP="/libexec/hooks/early-setup.d/luks-unlock.sh ; import_pool ${POOL_NAME}"
            POST_UNLOCK_WAIT=10
            ;;
        *)
            echo "ERROR: unknown VARIANT: $VARIANT (expected NOENC, ZFSENC, or LUKS)"
            kill $VM_PID 2>/dev/null || true
            exit 1
            ;;
    esac

    # ssh -n keeps this backgrounded connection from ever touching the caller's
    # stdin (matters when this script is called from a `while read < file` loop).
    (ssh -n $DROPBEAR_OPTS -p $DROPBEAR_PORT root@localhost 'bash -l -c "sleep 5 ; echo '"'password'"' | '"$UNLOCK_STEP"' ; sleep '"$POST_UNLOCK_WAIT"' ; find_be_kernels '"$DATASET"' ; sleep 2 ; kexec_kernel \"\$(select_kernel '"$DATASET"')\"" ') &
    UNLOCK_PID=$!
    echo "Unlock ssh is pid $UNLOCK_PID"

    # Step 3b: Wait for OpenSSH on the main OS (post-kexec)
    test_ssh ${SSH_PORT} 3b
    # Give system a moment to fully initialize after SSH starts
    sleep 5

    # Kill the unlock SSH session - it hangs waiting after kexec_kernel completes
    kill $UNLOCK_PID 2>/dev/null || true
fi

# Step 4: Install goss on VM
echo "[4/6] Installing goss on VM..."
# All ssh/scp calls below use -n / </dev/null so this script is safe to invoke
# from inside a `while read <file; do ...; done` loop without draining stdin.
# sshpass -p 'packer' ssh -n $SSH_OPTS -p $SSH_PORT $MAIN_USER@localhost "mkdir -p /home/${MAIN_USER}/.local/bin && if [ ! -e /home/${MAIN_USER}/.local/bin/goss ] ; then curl -fsSL https://goss.rocks/install | GOSS_DST=/home/${MAIN_USER}/.local/bin sh ; fi"
sshpass -p 'packer' ssh -n $SSH_OPTS -p $SSH_PORT $MAIN_USER@localhost "mkdir -p /home/${MAIN_USER}/.local/bin && if [ ! -e /home/${MAIN_USER}/.local/bin/goss ] ; then curl -L https://github.com/goss-org/goss/releases/latest/download/goss-linux-amd64 -o /home/${MAIN_USER}/.local/bin/goss ; chmod +x /home/${MAIN_USER}/.local/bin/goss ; fi"

# Step 5: Copy test files to VM
echo "[5/6] Copying test files..."
sshpass -p 'packer' scp $SSH_OPTS -P $SSH_PORT -r "${SCRIPT_DIR}/packer-validation" $MAIN_USER@localhost: </dev/null

# Step 6: Run goss validation
echo "[6/6] Running goss validation..."
echo ""
echo "=========================================="
echo "GOSS TEST OUTPUT"
echo "=========================================="

# Run goss, capturing output to a temp file while also streaming to stdout
GOSS_TMPFILE=$(mktemp /tmp/goss-output-XXXXXX)
sshpass -p 'packer' ssh -n $SSH_OPTS -p $SSH_PORT $MAIN_USER@localhost \
    "echo packer | sudo -S VALIDATION_DIR=/home/${MAIN_USER}/packer-validation /home/${MAIN_USER}/packer-validation/run-validation.sh" \
    | tee "$GOSS_TMPFILE" || true
GOSS_EXIT=${PIPESTATUS[0]}

echo "=========================================="
echo ""

# Save results to build directory if requested
if [[ "$SAVE_RESULTS" == "true" ]]; then
    TIMESTAMP=$(date +%Y-%m-%d-%H%M%S)
    RESULTS_FILE="${BUILD_DIR}/goss-validation-${TIMESTAMP}.txt"
    echo "Saving results to: $RESULTS_FILE"
    {
        echo "=== ZFS-root Goss Validation Results ==="
        echo "Date:     $(date)"
        echo "Build:    $BUILD_DIR"
        echo "Variant:  $VARIANT"
        echo "Suite:    $SUITE_NAME"
        echo "Pool:     $POOL_NAME"
        echo "Exit:     $GOSS_EXIT"
        echo ""
        cat "$GOSS_TMPFILE"
    } > "$RESULTS_FILE"
fi
rm -f "$GOSS_TMPFILE"

if [[ $GOSS_EXIT -eq 0 ]]; then
    echo "✅ All goss tests PASSED!"
else
    echo "❌ Some goss tests FAILED (exit code: $GOSS_EXIT)"
fi

# Cleanup
echo ""
echo "VM still running. To stop: kill $VM_PID"
echo "To SSH in: ssh -p $SSH_PORT packer@localhost"

exit $GOSS_EXIT
