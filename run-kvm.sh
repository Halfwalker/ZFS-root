#!/bin/bash

# This will run a packer-built system
# It assumes builds are in /qemu/builds/packer-...

usage() {
    cat << USAGE
Usage: ./run-kvm [OPTIONS] path-to-packer-build

SecureBoot is AUTO-DETECTED from build metadata. Manual override options:

Options:
  --bios          Run VM *without* UEFI (legacy BIOS mode)
  --secureboot    Force SecureBoot UEFI (overrides auto-detection)
  --ram SIZE      Set RAM size in MB (default: 2048)
  --ssh PORT      Set SSH forwarding port (default: 3222)
                  e.g. ssh -p 3222 packer@localhost -o pubkeyauthentication=no
                  Since packer builds default to packer:packer creds
  --dropbear PORT Set SSH forwarding port for Dropbear (default: 1222)
  --help          Show this help

  path-to-packer-build should be a directory created by
  ./run-packer.sh - typically in /qemu/builds

Secureboot auto-detection checks:
  1. build-metadata.txt for SECUREBOOT=true/false
  2. efivars.fd for Microsoft SecureBoot signatures
  3. Defaults to standard UEFI if detection fails
USAGE
}

# Default ram 2GB
RAMSIZE="${RAMSIZE:-2048}"
SSH_PORT="${SSH_PORT:-3222}"            # Main ssh port to booted system, NAT'd to ssh at 22
# Dropbear SSH port NAT'd to dropbear at 222
# Connect with 'ssh -p 1222 root@localhost`
DROPBEAR_PORT="${DROPBEAR_PORT:-1222}"  
OVMF=""                                 # Will be auto-detected or set by --secureboot flag

detect_secureboot() {
    local build_dir="$1"

    # Method 1: Check for build-metadata.txt (created by newer Packer builds)
    if [[ -f "${build_dir}/build-metadata.txt" ]]; then
        if grep -q "^SECUREBOOT=true" "${build_dir}/build-metadata.txt" 2>/dev/null; then
            return 0  # SecureBoot enabled
        else
            return 1  # SecureBoot disabled
        fi
    fi

    # Method 2: Check efivars.fd for Microsoft signatures (fallback for older builds)
    if [[ -f "${build_dir}/efivars.fd" ]]; then
        if strings "${build_dir}/efivars.fd" 2>/dev/null | grep -q "Microsoft Corporation"; then
            return 0  # SecureBoot enabled
        fi
    fi

    # Default: assume no SecureBoot
    return 1
}

# Auto-detect the correct OVMF_CODE firmware based on what's available
# Ubuntu 24.04+: OVMF_CODE_4M.fd / OVMF_CODE_4M.secboot.fd
# Ubuntu 18.04:  OVMF_CODE.fd (no SecureBoot variant available)
detect_ovmf_code() {
    local secureboot="${1:-false}"

    if [[ "$secureboot" == "true" ]]; then
        if [[ -f "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd" ]]; then
            echo "OVMF_CODE_4M.secboot.fd"
        elif [[ -f "/usr/share/OVMF/OVMF_CODE.secboot.fd" ]]; then
            echo "OVMF_CODE.secboot.fd"
        else
            # No SecureBoot firmware available — caller decides fallback
            echo ""
        fi
    else
        if [[ -f "/usr/share/OVMF/OVMF_CODE_4M.fd" ]]; then
            echo "OVMF_CODE_4M.fd"
        elif [[ -f "/usr/share/OVMF/OVMF_CODE.fd" ]]; then
            echo "OVMF_CODE.fd"
        else
            echo ""
        fi
    fi
}

detect_ovmf_vars() {
    if [[ -f "/usr/share/OVMF/OVMF_VARS_4M.fd" ]]; then
        echo "OVMF_VARS_4M.fd"
    elif [[ -f "/usr/share/OVMF/OVMF_VARS.fd" ]]; then
        echo "OVMF_VARS.fd"
    else
        echo ""
    fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bios)         BIOS=true ; shift ;;
    --secureboot)   OVMF=OVMF_CODE_4M.secboot.fd; shift ;;
    --ram)          RAMSIZE="$2" ; shift 2 ;;
    --ssh)          SSH_PORT="$2" ; shift 2 ;;
    --dropbear)     DROPBEAR_PORT="$2" ; shift 2 ;;
    --help)         usage; exit 0 ;;
    *)              ZFSROOT="$1" ; shift ;;
  esac
done

if [[ -z "$ZFSROOT" ]] ; then
    usage
    echo "Must provide a path to a packer build dir"
    if command -v fzf >/dev/null 2>&1; then
        echo "Pick one to boot or ESC to exit"
        ZFSROOT=$(find /qemu/builds/* -type d | fzf --height 20% --border --reverse --margin=5%,40%,0%,5%)
    else
        echo "For example, from here"
        find /qemu/builds/* -type d | xargs -I {} echo "$0 {}"
    fi
    [[ -z "$ZFSROOT" ]] && exit 1
fi

# Auto-detect SecureBoot if not explicitly set by --secureboot flag
if [[ -z "$OVMF" ]] && [[ -z "$BIOS" ]]; then
    # Step 1: detect whether the build has SecureBoot enabled
    secureboot_detected=false
    if detect_secureboot "$ZFSROOT"; then
        secureboot_detected=true
        echo "Auto-detected SecureBoot build"
    else
        echo "Auto-detected standard UEFI build"
    fi

    # Step 2: select matching OVMF firmware, falling back gracefully
    OVMF=$(detect_ovmf_code "$secureboot_detected")

    if [[ -z "$OVMF" ]]; then
        if [[ "$secureboot_detected" == "true" ]]; then
            # SecureBoot firmware not on this system — try standard
            OVMF=$(detect_ovmf_code false)
            if [[ -n "$OVMF" ]]; then
                echo "WARNING: SecureBoot OVMF not available — booting with ${OVMF} (no SecureBoot)"
                secureboot_detected=false
            fi
        fi
    fi

    if [[ -z "$OVMF" ]]; then
        echo "ERROR: No OVMF firmware found in /usr/share/OVMF/"
        ls /usr/share/OVMF/ 2>/dev/null || echo "  /usr/share/OVMF/ does not exist"
        exit 1
    fi

    if [[ "$secureboot_detected" == "true" ]]; then
        MACHINE_TYPE="q35"
        SMM_ENABLED="on"
        echo "  Using ${OVMF} with q35,smm=on"
    else
        MACHINE_TYPE="pc"
        SMM_ENABLED="off"
        echo "  Using ${OVMF}"
    fi
elif [[ -n "$OVMF" ]]; then
    # Manual --secureboot flag was used — verify the firmware exists
    if [[ ! -f "/usr/share/OVMF/${OVMF}" ]]; then
        detected=$(detect_ovmf_code true)
        if [[ -n "$detected" ]]; then
            OVMF="$detected"
            echo "Auto-detected SecureBoot firmware: ${OVMF}"
        else
            detected=$(detect_ovmf_code false)
            if [[ -n "$detected" ]]; then
                OVMF="$detected"
                echo "WARNING: SecureBoot OVMF not found, falling back to: ${OVMF}"
            else
                echo "ERROR: No OVMF firmware found in /usr/share/OVMF/"
                ls /usr/share/OVMF/ 2>/dev/null || echo "  /usr/share/OVMF/ does not exist"
                exit 1
            fi
        fi
    fi
    MACHINE_TYPE="q35"
    SMM_ENABLED="on"
    echo "SecureBoot manually enabled - using q35,smm=on"
else
    # Legacy BIOS mode
    MACHINE_TYPE="pc"
    SMM_ENABLED="off"
fi

# If booting with UEFI we need the UEFI bios and saved efivars
# $OVMF is set above and verified to exist on the system
if [[ -z "$BIOS" ]] ; then
    # Verify that the build's efivars.fd matches the system OVMF firmware size.
    # Builds created on a different OVMF version (e.g. 4M from 24.04 vs 2M from 18.04)
    # will have mismatched efivars.fd sizes and silently fail with a black screen.
    if [[ -f "${ZFSROOT}/efivars.fd" ]]; then
        # Derive expected vars filename from the detected OVMF_CODE file
        #   OVMF_CODE_4M.secboot.fd  → OVMF_VARS_4M.fd
        #   OVMF_CODE_4M.fd          → OVMF_VARS_4M.fd
        #   OVMF_CODE.fd             → OVMF_VARS.fd
        expected_vars=$(echo "$OVMF" | sed 's/OVMF_CODE/OVMF_VARS/; s/\.secboot//')
        expected_size=$(stat -c%s "/usr/share/OVMF/${expected_vars}" 2>/dev/null || echo 0)
        build_size=$(stat -c%s "${ZFSROOT}/efivars.fd")

        if [[ "$expected_size" -ne "$build_size" ]]; then
            echo "ERROR: Build efivars.fd is incompatible with this system's OVMF firmware."
            echo ""
            echo "  System OVMF_CODE:   /usr/share/OVMF/${OVMF}"
            echo "  Expected vars size:  ${expected_size} bytes (${expected_vars})"
            echo "  Build efivars.fd:    ${build_size} bytes (${ZFSROOT}/efivars.fd)"
            echo ""
            echo "This build was created on a system with a different OVMF version."
            echo "To boot it on this system you can either:"
            echo "  1. Rebuild the image on this system (recommended)"
            echo "  2. Install matching OVMF firmware on this system"
            echo "  3. Regenerate efivars.fd from the system template:"
            echo "     cp /usr/share/OVMF/${expected_vars} ${ZFSROOT}/efivars.fd"
            echo "     (WARNING: this will lose any SecureBoot keys in efivars.fd)"
            exit 1
        fi
    fi

    efivars=( -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/${OVMF} )
    efivars+=( -drive if=pflash,format=raw,file=${ZFSROOT}/efivars.fd )
fi

# Build machine type argument
if [[ "$SMM_ENABLED" == "on" ]]; then
    machine_args="-cpu host,+nx,+pae -machine ${MACHINE_TYPE},smm=on,accel=kvm"
    # Add global SMM options required for SecureBoot
    global_args="-global driver=cfi.pflash01,property=secure,value=on"
else
    machine_args="-cpu host,+nx,+pae -machine ${MACHINE_TYPE},accel=kvm"
    global_args=""
fi

# Add '-display none' for no gui interface when VM starts
qemu-system-x86_64 -no-reboot -m ${RAMSIZE} \
    ${machine_args} \
    ${global_args} \
    -daemonize -pidfile /tmp/qemu-vm.pid \
    ${efivars[*]} \
    $(for f in ${ZFSROOT}/*qcow* ; do echo "-drive file=${f},format=qcow2,cache=writeback " ; done) \
    -device virtio-scsi-pci,id=scsi0 \
    -device virtio-net-pci,netdev=net0 \
    -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::${DROPBEAR_PORT}-:222   # KVM-local network, need NAT to ssh in
    # -netdev bridge,id=net0,br=br0 &   # Attach to bridge br0 for local networking

# Write the QEMU PID to a file for scripts that need to track it
# echo $! > /tmp/qemu-vm.pid
echo "QEMU started with PID $(cat /tmp/qemu-vm.pid)"
