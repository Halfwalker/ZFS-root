#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: ./run-packer.sh [options]

NOTE: Defaults to /qemu as main working directory

Options:
  --docker                  Run packer in a docker container
  --config                  config for ZFS-root.sh - default ZFS-root.conf.packerci
  --discenc VALUE           (e.g. NOENC, ZFSENC, LUKS)
  --ubuntu-version VALUE    (e.g. 24.04.2)
  --ubuntu-name VALUE       (e.g. noble) [optional; auto-derived from version if not provided]
  --output-prefix VALUE     (e.g. /qemu/builds/)
  --disk-size VALUE         (e.g. 5G)
  --disks VALUE             (e.g. 3) [optional total; for multiple disks]
  --raidlevel VALUE         (e.g. raidz1 or mirror) only for multiple disks
  --secureboot              Enable SecureBoot (requires q35 machine and secboot OVMF firmware)
                            Also sets SECUREBOOT=y for the ZFS-root.sh config
                            Must manually set "--set AUTOSIGN=y" if auto-signing of boot files required
  --iso-src VALUE           (e.g. file:///qemu/ISOs) defaults to download
  --set KEY=VALUE           Override config variables (can be used multiple times)
  --help                    Show this help

For local ISOs, each ISO should be in the appropriate release-named dir
             ⬇⬇⬇⬇⬇
  /qemu/ISOs/focal/ubuntu-20.04.5-live-server-amd64.iso
  /qemu/ISOs/jammy/ubuntu-22.04.5-live-server-amd64.iso
  /qemu/ISOs/noble/ubuntu-24.04.2-live-server-amd64.iso
  /qemu/ISOs/plucky/ubuntu-25.04-live-server-amd64.iso
  /qemu/ISOs/questing/ubuntu-25.10-live-server-amd64.iso
  /qemu/ISOs/resolute/ubuntu-26.04-live-server-amd64.iso
             ⬆️⬆️⬆️⬆️⬆️⬆️⬆️⬆️

# Simplest usage - ubuntu-name is auto-derived from version
./run-packer.sh --ubuntu-version 24.04.2 --discenc NOENC --disk-size 5G

# Full example with all options (ubuntu-name optional)
./run-packer.sh \
  --docker \
  --discenc NOENC \
  --ubuntu-version 24.04.2 \
  --output-prefix /qemu/builds/ \
  --disk-size 5G \
  --disks 2 \
  --raidlevel mirror \
  --secureboot \
  --iso-src file:///qemu/ISOs \
  --set MYHOSTNAME=myserver \
  --set POOLNAME=zroot

# In github actions workflow matrix (can omit ubuntu-name now)
./run-packer.sh \
  --discenc "${{ matrix.discenc }}" \
  --ubuntu-version "${{ matrix.ubuntu_version }}" \
  --disk-size "${{ matrix.disk_size }}"
USAGE
}

# Set main qemu working dir
QEMU_ROOT="${QEMU_ROOT:-/qemu}"

# Used for serial logs when "-serial ..." is enabled in ZFS-root_local.pkr.hcl
# mkdir -p "${QEMU_ROOT}/logs"

DOCKER_RUN="${DOCKER_RUN:-}"                            # Run packer in container or not
CONFIG_FILE="${CONFIG_FILE:-ZFS-root.conf.packerci}"    # Preseed config file for ZFS-root.sh
DISCENC="${DISCENC:-NOENC}"                             # Disk encryption
VER="${VER:-24.04.2}"                                   # Ubuntu release to install
NAME="${NAME:-}"                                        # Ubuntu release name
OUT_PREFIX="${OUT_PREFIX:-${QEMU_ROOT}/builds/}"        # Output dir for packer artifacts
DISK_SIZE="${DISK_SIZE:-8G}"                            # Disk size (matches ZFS-root_local.pkr.hcl default)
DISKS="${DISKS:-}"                                      # Total number of disks if not 1
RAIDLEVEL="${RAIDLEVEL:-}"                              # Raid type for multi-disk (mirror, raidz1)
SECUREBOOT="${SECUREBOOT:-}"                            # Enable SecureBoot
ISO_SRC="${ISO_SRC:-}"                                  # Location of bootable ISOs (eg. file///qemu/ISOs)
CONFIG_OVERRIDES=()                                     # Array to collect --set KEY=VALUE pairs

while [[ $# -gt 0 ]]; do
    case "$1" in
        --docker)           DOCKER_RUN=true ; shift ;;
        --config)           CONFIG_FILE="$2" ; shift 2 ;;
        --discenc)          DISCENC="$2"; shift 2 ;;
        --ubuntu-version)   VER="$2"; shift 2 ;;
        --ubuntu-name)      NAME="$2"; shift 2 ;;
        --output-prefix)    OUT_PREFIX="$2"; shift 2 ;;
        --disk-size)        DISK_SIZE="$2"; shift 2 ;;
        --disks)            DISKS="$2"; shift 2 ;;
        --raidlevel)        RAIDLEVEL="$2"; shift 2 ;;
        --secureboot)       SECUREBOOT="true"; shift ;;
        --iso-src)          ISO_SRC="$2"; shift 2 ;;
        --set)
            # Validate KEY=VALUE format
            if [[ ! "$2" =~ ^[A-Z_][A-Z0-9_]*=.+$ ]]; then
                echo "Error: --set requires KEY=VALUE format (e.g., MYHOSTNAME=myhost)" >&2
                exit 1
            fi
            CONFIG_OVERRIDES+=("$2")
            shift 2
            ;;
        --help|-h)          usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ ! -e "${CONFIG_FILE}" ]] ; then
    echo "Preseed config file ${CONFIG_FILE} does not exist"
    exit 1
fi

if [[ ! -d "${QEMU_ROOT}" ]] ; then
    echo "Main qemu dir ${QEMU_ROOT} does not exist"
    exit 1
fi

if [[ ! -d "${QEMU_ROOT}/builds" ]] ; then
    echo "packer builds dir ${QEMU_ROOT}/builds does not exist"
    exit 1
fi

# Auto-derive ubuntu_version_name if not provided
# NOTE: The Packer config also does this derivation, so this is mainly for
# validation and to provide better error messages at the script level
if [[ -z "$NAME" && -n "$VER" ]]; then
    case "$VER" in
        26.04* ) NAME="resolute" ;;
        25.10* ) NAME="questing" ;;
        25.04* ) NAME="plucky" ;;
        24.04* ) NAME="noble" ;;
        22.04* ) NAME="jammy" ;;
        20.04* ) NAME="focal" ;;
        18.04* ) NAME="bionic" ;;
        *)
          echo "Unknown ubuntu_version '$VER' — please set --ubuntu-name explicitly." >&2
          exit 1
          ;;
    esac
fi

# If --secureboot was specified, ensure ZFS-root.sh also enables SecureBoot
if [[ "${SECUREBOOT}" == "true" ]]; then
    CONFIG_OVERRIDES+=("SECUREBOOT=y")
fi

# Auto-detect OVMF firmware paths
# Ubuntu 24.04+: OVMF_CODE_4M.fd / OVMF_VARS_4M.fd
# Ubuntu 18.04:  OVMF_CODE.fd / OVMF_VARS.fd
if [[ -f "/usr/share/OVMF/OVMF_CODE_4M.fd" ]]; then
    OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
    OVMF_CODE_SECBOOT="/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
    OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"
    echo "Using 4M version of OVMF uefi code"
elif [[ -f "/usr/share/OVMF/OVMF_CODE.fd" ]]; then
    OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
    OVMF_CODE_SECBOOT=""  # 18.04 has no .secboot.fd variant
    OVMF_VARS="/usr/share/OVMF/OVMF_VARS.fd"
    echo "Using old version of OVMF uefi code"
else
    echo "ERROR: No OVMF firmware found in /usr/share/OVMF/"
    exit 1
fi

# For SecureBoot builds, use the .secboot firmware if available
if [[ "${SECUREBOOT}" == "true" && -n "${OVMF_CODE_SECBOOT}" ]]; then
    OVMF_CODE="${OVMF_CODE_SECBOOT}"
    echo "Using SecureBoot OVMF firmware: ${OVMF_CODE}"
fi

echo "Detected OVMF firmware: ${OVMF_CODE}, ${OVMF_VARS}"

packer_args=( -var-file=ZFS-root_local.vars.hcl )

add_var() {
    local var_name="$1"
    local val="$2"
    if [[ -n "$val" ]]; then
        packer_args+=( -var "${var_name}=${val}" )
    fi
}

add_var "discenc"             "$DISCENC"
add_var "ubuntu_version"      "$VER"
add_var "ubuntu_version_name" "$NAME"
add_var "output_prefix"       "$OUT_PREFIX"
add_var "disk_size"           "$DISK_SIZE"
add_var "raidlevel"           "$RAIDLEVEL"
add_var "secureboot"          "$SECUREBOOT"
add_var "ovmf_code"           "$OVMF_CODE"
add_var "ovmf_vars"           "$OVMF_VARS"
add_var "ubuntu_live_iso_src" "$ISO_SRC"
add_var "config_file"         "$CONFIG_FILE"

# Build config_overrides map from --set parameters
if [[ ${#CONFIG_OVERRIDES[@]} -gt 0 ]]; then
    # Build JSON-style map for PKR_VAR_config_overrides env var
    overrides_map="{"
    for i in "${!CONFIG_OVERRIDES[@]}"; do
        # Split KEY=VALUE
        key="${CONFIG_OVERRIDES[$i]%%=*}"
        value="${CONFIG_OVERRIDES[$i]#*=}"

        # Escape any double quotes in the value
        escaped_value="${value//\"/\\\"}"

        # Add to map with quoted keys and values (using colon for JSON-style syntax)
        if [[ $i -eq 0 ]]; then
            overrides_map+="\"${key}\":\"${escaped_value}\""
        else
            overrides_map+=",\"${key}\":\"${escaped_value}\""
        fi
    done
    overrides_map+="}"

    # Export as env var instead of -var to avoid shell argument splitting
    # on values containing spaces (e.g. SSH public keys)
    export PKR_VAR_config_overrides="${overrides_map}"

    echo "Config overrides: ${CONFIG_OVERRIDES[*]}"
fi


# Running in docker requires headless, but running direct/local we can
# view the install directly if a display is available
if [[ ! -n "${DOCKER_RUN}" ]] ; then
    if [[ -n "${DISPLAY:-}" ]]; then
        add_var "headless" "false"
        echo "Display available — showing VM console"
    else
        echo "No display available — running headless automatically"
    fi
fi

check_disks() {
    # Check if DISKS is set and validate it
    if [[ -n "${DISKS}" ]]; then
        # Verify DISKS is a number
        if ! [[ "${DISKS}" =~ ^[0-9]+$ ]]; then
            echo "Error: DISKS must be a positive integer, got: ${DISKS}" >&2
            exit 1
        fi

        # Only process if DISKS > 1
        if [[ "${DISKS}" -gt 1 ]]; then
            # Check that DISK_SIZE is set
            if [[ -z "${DISK_SIZE}" ]]; then
                echo "Error: DISK_SIZE must be set when using multiple disks" >&2
                exit 1
            fi

            # Calculate number of additional disks
            additional_count=$((DISKS - 1))

            # Build the array string with escaped quotes for sh -c
            disk_array=""
            for ((i=0; i<additional_count; i++)); do
                if [[ $i -eq 0 ]]; then
                    disk_array="\\\"${DISK_SIZE}\\\""
                else
                    disk_array="${disk_array},\\\"${DISK_SIZE}\\\""
                fi
            done

            # Add to packer_args
            packer_args+=( -var "additional_disks=[${disk_array}]" )

            echo "Adding ${additional_count} additional disk(s) of size ${DISK_SIZE}"
        fi
    fi
}

packer_init_docker() {
    # Install packer qemu plugin
    echo "Init packer and download packer-qemu plugin"

    docker run --rm -it \
      --privileged --cap-add=ALL \
      -v "$(pwd)":"${PWD}" -w "${PWD}" \
      -v ${QEMU_ROOT}/packer.d:/root/.cache/packer.d \
      -e PACKER_PLUGIN_PATH="/root/.cache/packer.d/plugins" \
      --entrypoint /bin/sh \
      hashicorp/packer:light -c "packer init ZFS-root_local.pkr.hcl"
}

packer_docker() {
    # Run packer in a docker container
    docker_args=( -v /usr/share/OVMF:/usr/share/OVMF )

    # Used for serial logs when "-serial ..." is enabled in ZFS-root_local.pkr.hcl
    [ -d ${QEMU_ROOT}/logs ] && docker_args+=( -v /qemu/logs:/qemu/logs )

    # If ISO_SRC is not defined, then the packer config will default to pulling
    # the iso from https://releases.ubuntu.com
    if [[ -n "${ISO_SRC}" ]] && [[ "${ISO_SRC}" =~ "file:///" ]] ; then
        ISO_DIR=${ISO_SRC#file://}
        if [[ ! -d "${ISO_DIR}" ]] ; then
            echo "ISO src dir ${ISO_DIR} does not exist"
            exit 1
        else
            docker_args+=( -v ${ISO_DIR}:/qemu/ISOs )
        fi
    fi

    echo "Docker args ${docker_args[*]}"

    # Install the packer qemu plugin if necessary
    if [ ! -d ${QEMU_ROOT}/packer.d/plugins/github.com/hashicorp/qemu ] ; then
        packer_init_docker
    fi

    # Check host kernel for QEMU compatibility
    # QEMU >= 11 from Alpine edge has a SLiRP regression on kernel < 6.0
    KERNEL_MAJOR=$(uname -r | cut -d. -f1)
    if [ "$KERNEL_MAJOR" -lt 6 ]; then
        QEMU_PKG="qemu-system-x86_64=8.1.5-r0"
        QEMU_REPO="--repository http://dl-cdn.alpinelinux.org/alpine/v3.19/community"
        echo "Kernel ${KERNEL_MAJOR}.x detected — using QEMU 8.1.5 for compatibility"
    else
        QEMU_PKG="qemu-system-x86_64"
        QEMU_REPO=""
    fi

    docker run --rm -it \
      --privileged --cap-add=ALL \
      -v "$(pwd)":"${PWD}" -w "${PWD}" \
      ${docker_args[*]} \
      -v ${QEMU_ROOT}/packer.d:/root/.cache/packer.d \
      -v ${QEMU_ROOT}/builds:/qemu/builds \
      -e PACKER_PLUGIN_PATH="/root/.cache/packer.d/plugins" \
      -e PACKER_LOG=1 \
      -e PKR_VAR_config_overrides \
      --entrypoint /bin/sh \
      hashicorp/packer:light -c " \
        apk add --no-cache ${QEMU_PKG} qemu-img ${QEMU_REPO} >/dev/null 2>&1 && \
        packer build ${packer_args[*]} ZFS-root_local.pkr.hcl"
}

packer_init_direct() {
    # Install packer qemu plugin
    echo "Init packer and download packer-qemu plugin"

    export PACKER_PLUGIN_PATH=${QEMU_ROOT}/packer.d/plugins
    packer init ZFS-root_local.pkr.hcl
}

packer_direct() {
    # Install the packer qemu plugin if necessary
    if [ ! -d ${QEMU_ROOT}/packer.d/plugins/github.com/hashicorp/qemu ] ; then
        packer_init_direct
    fi

    export PACKER_PLUGIN_PATH=${QEMU_ROOT}/packer.d/plugins
    export PACKER_LOG=1

    # Use fifo + tee for live output while capturing to file
    trap 'rm -f /tmp/packer-pipe; kill $TEE_PID 2>/dev/null || true' EXIT
    mkfifo /tmp/packer-pipe
    tee /tmp/packer-output.log < /tmp/packer-pipe &
    TEE_PID=$!

    packer build ${packer_args[*]} ZFS-root_local.pkr.hcl > /tmp/packer-pipe

    BUILD_EXIT=$?
    wait $TEE_PID

    # Extract output directory from packer log
    OUTPUT_DIR=$(grep -o '/qemu/builds/packer-[^/]*' /tmp/packer-output.log | head -1)
    if [ -n "$OUTPUT_DIR" ] && [ -d "$OUTPUT_DIR" ]; then
      cp /tmp/packer-output.log "$OUTPUT_DIR/packer-output.log"
    fi
}

check_disks

echo "Starting build with ${packer_args[*]}"
if [[ -n "${DOCKER_RUN}" ]] ; then
    packer_docker
else
    packer_direct
fi

