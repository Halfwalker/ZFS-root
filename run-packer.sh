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
  --ramdisk SIZE            Use raw disk(s) on a host-mounted tmpfs (e.g. 16G); without it, the normal QCOW2 output path is unchanged
  --disk-size VALUE         (e.g. 8G)
  --disks VALUE             (e.g. 3) [optional total; for multiple disks]
  --raidlevel VALUE         (e.g. raidz1 or mirror) only for multiple disks
  --secureboot              Enable SecureBoot (requires q35 machine and secboot OVMF firmware)
                            Also sets SECUREBOOT=y for the ZFS-root.sh config
                            Must manually set "--set AUTOSIGN=y" if auto-signing of boot files required
  --iso-src VALUE           (e.g. file:///qemu/ISOs) defaults to download
  --set KEY=VALUE           Override config variables (can be used multiple times)
  --display VALUE           packer display defaults to "sdl", can set to "gtk"
  --help                    Show this help

For local ISOs, each ISO should be in the appropriate release-named dir
             ⬇⬇⬇⬇⬇
  /qemu/ISOs/focal/ubuntu-20.04.5-live-server-amd64.iso
  /qemu/ISOs/jammy/ubuntu-22.04.5-live-server-amd64.iso
  /qemu/ISOs/noble/ubuntu-24.04.2-live-server-amd64.iso
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
PACKER_DISPLAY="${PACKER_DISPLAY:-}"                    # Override packer display var
# RAM mode is strictly opt-in. Empty preserves the established QCOW2 build and
# launch paths, while a size enables the tmpfs staging/promotion lifecycle.
RAMDISK_SIZE=""
RAMDISK_MOUNTED=false
# The build ID names the eventual artifact directory; the work directory is its
# disposable tmpfs mount; stage output is Packer's required new directory; final
# directory has promoted metadata and RAM-backed disk mounts.
RAM_BUILD_ID=""
RAM_WORK_DIR=""
RAM_STAGE_OUTPUT=""
RAM_FINAL_DIR=""
# Final disk paths are individual bind mounts and must be unmounted before any
# failure cleanup can remove the corresponding staging tmpfs.
RAM_FINAL_MOUNTS=()
RAMDISK_SUDO=()
RAMDISK_OWNER="$(id -u):$(id -g)"
CONFIG_OVERRIDES=()                                     # Array to collect --set KEY=VALUE pairs

while [[ $# -gt 0 ]]; do
    case "$1" in
        --docker)           DOCKER_RUN=true ; shift ;;
        --config)           CONFIG_FILE="$2" ; shift 2 ;;
        --discenc)          DISCENC="$2"; shift 2 ;;
        --ubuntu-version)   VER="$2"; shift 2 ;;
        --ubuntu-name)      NAME="$2"; shift 2 ;;
        --output-prefix)    OUT_PREFIX="$2"; shift 2 ;;
        --ramdisk)          RAMDISK_SIZE="$2"; shift 2 ;;
        --disk-size)        DISK_SIZE="$2"; shift 2 ;;
        --disks)            DISKS="$2"; shift 2 ;;
        --raidlevel)        RAIDLEVEL="$2"; shift 2 ;;
        --secureboot)       SECUREBOOT="true"; shift ;;
        --iso-src)          ISO_SRC="$2"; shift 2 ;;
        --display)          PACKER_DISPLAY="$2"; shift 2 ;;
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

if [[ -n "${RAMDISK_SIZE}" && "${OUT_PREFIX}" != "${QEMU_ROOT}/builds/" ]]; then
    echo "Error: --ramdisk cannot be combined with --output-prefix" >&2
    exit 1
fi

if [[ -n "${RAMDISK_SIZE}" && ! "${RAMDISK_SIZE}" =~ ^[1-9][0-9]*[KMGTP]?$ ]]; then
    echo "Error: --ramdisk requires a positive size with an optional K, M, G, T, or P suffix" >&2
    exit 1
fi

if [[ -n "${RAMDISK_SIZE}" ]]; then
    for command_name in mount umount findmnt; do
        if ! command -v "${command_name}" >/dev/null 2>&1; then
            echo "Error: --ramdisk requires ${command_name}" >&2
            exit 1
        fi
    done
fi

if [[ -n "${RAMDISK_SIZE}" && "${EUID}" -ne 0 ]]; then
    # Mounting tmpfs and later bind mounts require host privilege. Keep sudo
    # scoped to those filesystem operations rather than running Packer as root.
    if ! command -v sudo >/dev/null 2>&1; then
        echo "Error: --ramdisk requires sudo when not run as root" >&2
        exit 1
    fi
    RAMDISK_SUDO=(sudo)
fi

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
add_var "display"             "$PACKER_DISPLAY"

ramdisk_failure_cleanup() {
    local status="$?" mount_target
    if [[ "${status}" -ne 0 ]]; then
        # Include enough lifecycle state to diagnose failures after the tmpfs is
        # gone, then reverse promotion: disk bind mounts first, staging last.
        echo "RAM build failure diagnostics: status=${status} RAM_WORK_DIR=${RAM_WORK_DIR:-} RAM_STAGE_OUTPUT=${RAM_STAGE_OUTPUT:-} RAM_BUILD_ID=${RAM_BUILD_ID:-} RAM_FINAL_MOUNTS=${RAM_FINAL_MOUNTS[*]:-}" >&2
    fi
    if [[ "${status}" -ne 0 ]]; then
        # RAM disk files are individual bind mounts. Unmount them before their
        # staging tmpfs so mounted targets are never removed during cleanup.
        for mount_target in "${RAM_FINAL_MOUNTS[@]}"; do
            "${RAMDISK_SUDO[@]}" umount "${mount_target}" || true
        done
        if [[ "${RAM_FINAL_DIR:-}" == "${QEMU_ROOT}/builds/packer-"* ]]; then
            rm -rf -- "${RAM_FINAL_DIR}" || true
        fi
    fi
    if [[ "${status}" -ne 0 && "${RAMDISK_MOUNTED}" == "true" ]]; then
        if [[ -f "${RAM_WORK_DIR}/packer-output.log" ]]; then
            "${RAMDISK_SUDO[@]}" cp "${RAM_WORK_DIR}/packer-output.log" "${QEMU_ROOT}/builds/${RAM_BUILD_ID}.failed-packer-output.log" || true
            "${RAMDISK_SUDO[@]}" chown "${RAMDISK_OWNER}" "${QEMU_ROOT}/builds/${RAM_BUILD_ID}.failed-packer-output.log" || true
            echo "Preserved Packer output at ${QEMU_ROOT}/builds/${RAM_BUILD_ID}.failed-packer-output.log" >&2
        fi
        echo "Build failed; unmounting staging tmpfs ${RAM_WORK_DIR}" >&2
        "${RAMDISK_SUDO[@]}" umount "${RAM_WORK_DIR}" || true
        if [[ "${RAM_WORK_DIR}" == "${QEMU_ROOT}/builds/.ramdisk-work/"* ]]; then
            rmdir "${RAM_WORK_DIR}" 2>/dev/null || true
        fi
    fi
    exit "${status}"
}

prepare_ramdisk() {
    local attempt

    RAM_BUILD_ID="packer-${NAME}-${DISCENC}-$(date +%Y%m%d-%H%M%S)-$$"
    attempt="${RAM_BUILD_ID}.work"
    RAM_WORK_DIR="${QEMU_ROOT}/builds/.ramdisk-work/${attempt}"
    RAM_STAGE_OUTPUT="${RAM_WORK_DIR}/${RAM_BUILD_ID}"

    # The host needs writable builds/.ramdisk-work plus sudo-capable tmpfs mount
    # tools. Create the mount point before either direct or Docker Packer starts
    # so both execution modes see the same host-backed staging location.
    mkdir -p "${QEMU_ROOT}/builds/.ramdisk-work"
    if [[ -e "${RAM_WORK_DIR}" || -e "${QEMU_ROOT}/builds/${RAM_BUILD_ID}" ]]; then
        echo "Error: RAM-disk work or final build directory already exists" >&2
        exit 1
    fi
    mkdir "${RAM_WORK_DIR}"
    if ! "${RAMDISK_SUDO[@]}" mount -t tmpfs -o "size=${RAMDISK_SIZE}" tmpfs "${RAM_WORK_DIR}"; then
        rmdir "${RAM_WORK_DIR}" 2>/dev/null || true
        echo "Error: failed to mount tmpfs at ${RAM_WORK_DIR}" >&2
        exit 1
    fi
    RAMDISK_MOUNTED=true
    if [[ "$(findmnt -n -o FSTYPE --target "${RAM_WORK_DIR}")" != "tmpfs" ]]; then
        echo "Error: ${RAM_WORK_DIR} is not a tmpfs mount" >&2
        exit 1
    fi

    # The QEMU plugin refuses an existing output_directory. Packer therefore
    # creates RAM_STAGE_OUTPUT under this new tmpfs mount; promotion later gives
    # the artifacts their normal builds/<build-id> location.
    add_var "output_prefix" "${RAM_WORK_DIR}/"
    add_var "build_id" "${RAM_BUILD_ID}"
    add_var "ramdisk_mode" "true"
    trap ramdisk_failure_cleanup EXIT
    echo "Using staging tmpfs ${RAM_WORK_DIR} (${RAMDISK_SIZE})"
}

promote_ramdisk_build() {
    local final_dir disk_name metadata_paths artifact mount_target
    local -a disk_names artifacts

    final_dir="${QEMU_ROOT}/builds/${RAM_BUILD_ID}"
    [[ -f "${RAM_STAGE_OUTPUT}/build-metadata.txt" ]] || { echo "Error: missing RAM build metadata" >&2; return 1; }
    metadata_paths=$("${RAMDISK_SUDO[@]}" awk -F= '$1 == "DISK_PATHS" { print $2; exit }' "${RAM_STAGE_OUTPUT}/build-metadata.txt")
    IFS=',' read -r -a disk_names <<< "${metadata_paths}"
    [[ ${#disk_names[@]} -eq ${DISKS:-1} ]] || { echo "Error: RAM disk metadata has an unexpected disk count" >&2; return 1; }

    for disk_name in "${disk_names[@]}"; do
        if [[ ! "${disk_name}" =~ ^(disk\.raw|packer-[A-Za-z0-9._-]+\.raw)(-[1-9][0-9]*)?$ || ! -f "${RAM_STAGE_OUTPUT}/${disk_name}" ]]; then
            echo "Error: unsafe or missing RAM disk ${disk_name}" >&2
            return 1
        fi
    done
    [[ ! -e "${final_dir}" ]] || { echo "Error: refusing to overwrite existing final build directory ${final_dir}" >&2; return 1; }

    artifacts=(efivars.fd build.log manifest.json build-metadata.txt ZFS-root_final.conf checksums.sha256)
    mkdir "${final_dir}" || { echo "Error: failed to create final build directory ${final_dir}" >&2; return 1; }
    RAM_FINAL_DIR="${final_dir}"
    for artifact in "${artifacts[@]}"; do
        if [[ -f "${RAM_STAGE_OUTPUT}/${artifact}" ]]; then
            # Docker Packer can leave staging files root-owned. Use sudo only to
            # copy/chown these known artifacts, then leave final files user-owned.
            "${RAMDISK_SUDO[@]}" cp "${RAM_STAGE_OUTPUT}/${artifact}" "${final_dir}/${artifact}" || { echo "Error: failed to copy RAM artifact ${artifact}" >&2; return 1; }
            "${RAMDISK_SUDO[@]}" chown "${RAMDISK_OWNER}" "${final_dir}/${artifact}" || { echo "Error: failed to set ownership on RAM artifact ${artifact}" >&2; return 1; }
        fi
    done

    if [[ -f "${RAM_WORK_DIR}/packer-output.log" ]]; then
        "${RAMDISK_SUDO[@]}" cp "${RAM_WORK_DIR}/packer-output.log" "${final_dir}/packer-output.log" || { echo "Error: failed to copy RAM Packer output" >&2; return 1; }
        "${RAMDISK_SUDO[@]}" chown "${RAMDISK_OWNER}" "${final_dir}/packer-output.log" || { echo "Error: failed to set ownership on RAM Packer output" >&2; return 1; }
    fi

    # Disk names come from Packer's metadata rather than being reconstructed here.
    # Packer must stage in a unique tmpfs directory because its output_directory
    # cannot pre-exist dammit. Binding each raw file at its normal final artifact path
    # retains the tmpfs inode after staging is unmounted, without a ramdisk/ path.
    for disk_name in "${disk_names[@]}"; do
        mount_target="${final_dir}/${disk_name}"
        install -m 0600 /dev/null "${mount_target}" || { echo "Error: failed to create RAM disk mount target ${mount_target}" >&2; return 1; }
        "${RAMDISK_SUDO[@]}" chown "${RAMDISK_OWNER}" "${RAM_STAGE_OUTPUT}/${disk_name}" || { echo "Error: failed to set ownership on RAM disk ${disk_name}" >&2; return 1; }
        "${RAMDISK_SUDO[@]}" mount --bind "${RAM_STAGE_OUTPUT}/${disk_name}" "${mount_target}" || { echo "Error: failed to bind RAM disk ${disk_name}" >&2; return 1; }
        RAM_FINAL_MOUNTS+=("${mount_target}")
        if [[ "$(findmnt -n -o FSTYPE --target "${mount_target}")" != "tmpfs" ]]; then
            echo "Error: RAM disk bind mount is not tmpfs-backed: ${mount_target}" >&2
            return 1
        fi
    done

    # Once every file bind mount is verified, remove the staging mount. Final
    # mounts retain the RAM-backed inodes; failure cleanup reverses this order.
    "${RAMDISK_SUDO[@]}" umount "${RAM_WORK_DIR}" || { echo "Error: failed to unmount RAM staging tmpfs ${RAM_WORK_DIR}" >&2; return 1; }
    RAMDISK_MOUNTED=false
    "${RAMDISK_SUDO[@]}" rmdir "${RAM_WORK_DIR}" || { echo "Error: failed to remove RAM staging directory ${RAM_WORK_DIR}" >&2; return 1; }
}

promote_ramdisk_build_with_diagnostics() {
    local promotion_log="${QEMU_ROOT}/builds/${RAM_BUILD_ID}.promotion.log" status

    # Keep tracing in this shell so RAM_FINAL_MOUNTS remains available to
    # failure cleanup. Capture promotion diagnostics quietly unless it fails,
    # when the retained log identifies the failed copy, ownership, or mount step.
    exec 6>&1 7>&2
    exec >"${promotion_log}" 2>&1
    exec 5>&1
    BASH_XTRACEFD=5
    set -x
    if promote_ramdisk_build; then
        status=0
    else
        status=$?
    fi
    set +x
    exec 1>&6 2>&7 5>&- 6>&- 7>&-
    unset BASH_XTRACEFD
    if [[ "${status}" -eq 0 ]]; then
        rm -f "${promotion_log}"
    else
        echo "RAM promotion failed; diagnostics retained at ${promotion_log}" >&2
        cat -- "${promotion_log}" >&2 || true
    fi
    return "${status}"
}

run_packer_with_ram_capture() {
    local status

    # RAM builds lose their staging tmpfs on failure, so retain a live copy of
    # combined Packer/Docker output. With set -e and pipefail, explicitly return
    # PIPESTATUS[0] so tee's result never masks the wrapped Packer/Docker status.
    if "$@" 2>&1 | tee "${RAM_WORK_DIR}/packer-output.log"; then
        status=${PIPESTATUS[0]}
    else
        status=${PIPESTATUS[0]}
    fi
    return "${status}"
}

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
        if ! [[ "${DISKS}" =~ ^[1-9][0-9]*$ ]]; then
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

    if [[ -n "${RAMDISK_SIZE}" ]]; then
      # RAM capture is separate so the normal Docker behavior and output remain
      # unchanged when --ramdisk was not requested.
      run_packer_with_ram_capture docker run --rm -it \
        --privileged --cap-add=ALL \
        -v "$(pwd)":"${PWD}" -w "${PWD}" \
        "${docker_args[@]}" \
        -v ${QEMU_ROOT}/packer.d:/root/.cache/packer.d \
        -v ${QEMU_ROOT}/builds:/qemu/builds \
        -e PACKER_PLUGIN_PATH="/root/.cache/packer.d/plugins" \
        -e PACKER_LOG=1 \
        -e PKR_VAR_config_overrides \
        --entrypoint /bin/sh \
        hashicorp/packer:light -c " \
          apk add --no-cache ${QEMU_PKG} qemu-img ${QEMU_REPO} >/dev/null 2>&1 && \
          packer build ${packer_args[*]} ZFS-root_local.pkr.hcl"
    else
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
    fi
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

    if [[ -n "${RAMDISK_SIZE}" ]]; then
      run_packer_with_ram_capture packer build ${packer_args[*]} ZFS-root_local.pkr.hcl
    else
      # Keep the legacy direct path separate: its FIFO logging and QCOW2 output
      # lifecycle predate and do not depend on RAM staging.
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
    fi
}

check_disks
if [[ -n "${RAMDISK_SIZE}" ]]; then
    prepare_ramdisk
fi

echo "Starting build with ${packer_args[*]}"
if [[ -n "${DOCKER_RUN}" ]] ; then
    packer_docker
else
    packer_direct
fi

if [[ -n "${RAMDISK_SIZE}" ]]; then
    promote_ramdisk_build_with_diagnostics
    trap - EXIT
    # Promotion is complete: tell the operator where the normal-looking build
    # directory and its still-RAM-backed disks live, plus the required cleanup.
    echo "RAM-backed build promoted: ${QEMU_ROOT}/builds/${RAM_BUILD_ID}" >&2
    echo "RAM-backed raw disk files: ${RAM_FINAL_MOUNTS[*]}" >&2
    for mount_target in "${RAM_FINAL_MOUNTS[@]}"; do
        echo "Verified RAM backing: $(findmnt -n -o TARGET,SOURCE,FSTYPE --target "${mount_target}")" >&2
        echo "Clean up after stopping QEMU: sudo umount ${mount_target}" >&2
    done
    # These mounts are intentionally left in place for run-kvm; removing them
    # releases RAM, so QEMU must be stopped before the printed cleanup commands.
    echo "These raw disk files consume RAM and are ephemeral; stop QEMU before unmounting them." >&2
fi
