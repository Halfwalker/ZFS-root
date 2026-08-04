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
    if detect_secureboot "$ZFSROOT"; then
        OVMF="OVMF_CODE_4M.secboot.fd"
        MACHINE_TYPE="q35"
        SMM_ENABLED="on"
        echo "Auto-detected SecureBoot build - using ${OVMF} with q35,smm=on"
    else
        OVMF="OVMF_CODE_4M.fd"
        MACHINE_TYPE="pc"
        SMM_ENABLED="off"
        echo "Auto-detected standard UEFI build - using ${OVMF}"
    fi
elif [[ -n "$OVMF" ]]; then
    # Manual --secureboot flag was used
    MACHINE_TYPE="q35"
    SMM_ENABLED="on"
    echo "SecureBoot manually enabled - using q35,smm=on"
else
    # Legacy BIOS mode
    MACHINE_TYPE="pc"
    SMM_ENABLED="off"
fi

# If booting with UEFI we need the UEFI bios and saved efivars
# Set above in $OVMF variable
if [[ -z "$BIOS" ]] ; then
    efivars=( -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/${OVMF} )
    efivars+=( -drive if=pflash,format=raw,file=${ZFSROOT}/efivars.fd )
fi

# Build machine type argument
if [[ "$SMM_ENABLED" == "on" ]]; then
    machine_args="-machine ${MACHINE_TYPE},smm=on,accel=kvm"
    # Add global SMM options required for SecureBoot
    global_args="-global driver=cfi.pflash01,property=secure,value=on"
else
    machine_args="-machine ${MACHINE_TYPE},accel=kvm"
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
