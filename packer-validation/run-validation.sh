#!/bin/bash
# ZFS-root Validation Runner
# Run on a booted VM to validate the installation
#
# Usage: ./run-validation.sh [--format documentation|json|tap|junit]
# Environment variables:
#   GOSS_FORMAT - Output format (default: documentation)
#   GOSS_VARS_FILE - Override vars file path
#   VALIDATION_DIR - Directory containing tests (default: $HOME/packer-validation)

set -e

# Configuration
# Default location when copied to user's home directory by ZFS-root.sh
VALIDATION_DIR="${VALIDATION_DIR:-$HOME/packer-validation}"
GOSS_FORMAT="${GOSS_FORMAT:-documentation}"
GOSS_BIN="${GOSS_BIN:-$HOME/.local/bin/goss}"
TEST_DIR="${VALIDATION_DIR}/tests"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root (required for ZFS commands)
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (required for ZFS commands)"
        exit 1
    fi
}

# Install goss if not present
install_goss() {
    if [[ -x "$GOSS_BIN" ]]; then
        log_info "Goss already installed: $($GOSS_BIN --version)"
        return 0
    fi

    log_info "Installing goss..."
    mkdir -p ~/.local/bin
    curl -L https://github.com/goss-org/goss/releases/latest/download/goss-linux-amd64 -o ~/.local/bin/goss
    chmod +x ~/.local/bin/goss

    # export GOSS_DST=~/.local/bin
    # curl -fsSL https://goss.rocks/install | sh
    
    if [[ -x "$GOSS_BIN" ]]; then
        log_info "Goss installed successfully: $($GOSS_BIN --version)"
    else
        log_error "Failed to install goss"
        exit 1
    fi
}

# Auto-detect system configuration
detect_config() {
    log_info "Detecting system configuration..."

    # Detect pool name (should be the only imported pool or named after distro)
    local pool_list
    pool_list=$(zpool list -H -o name 2>/dev/null || true)
    
    if [[ -z "$pool_list" ]]; then
        log_error "No ZFS pools found"
        exit 1
    fi

    # Use first pool if multiple exist
    DETECTED_POOL=$(echo "$pool_list" | head -1)
    log_info "Detected pool: $DETECTED_POOL"

    # Detect suite from bootfs
    local bootfs
    bootfs=$(zpool get -H -o value bootfs "$DETECTED_POOL" 2>/dev/null || true)
    if [[ -n "$bootfs" && "$bootfs" != "-" ]]; then
        DETECTED_SUITE=$(basename "$bootfs")
        log_info "Detected suite: $DETECTED_SUITE"
    else
        DETECTED_SUITE="$DETECTED_POOL"
        log_warn "Could not detect suite from bootfs, using pool name: $DETECTED_SUITE"
    fi

    # Detect encryption mode
    local encryption
    encryption=$(zfs get -H -o value encryption "${DETECTED_POOL}/ROOT" 2>/dev/null || echo "off")
    
    # Check for LUKS
    if [[ -e /dev/disk/by-partlabel/ZFS_0 ]]; then
        if cryptsetup isLuks /dev/disk/by-partlabel/ZFS_0 2>/dev/null; then
            DETECTED_ENC="LUKS"
        elif [[ "$encryption" != "off" ]]; then
            DETECTED_ENC="ZFSENC"
        else
            DETECTED_ENC="NOENC"
        fi
    else
        if [[ "$encryption" != "off" ]]; then
            DETECTED_ENC="ZFSENC"
        else
            DETECTED_ENC="NOENC"
        fi
    fi
    log_info "Detected encryption: $DETECTED_ENC"

    # Detect if zrepl is installed
    if command -v zrepl >/dev/null 2>&1 || [[ -f /etc/zrepl/zrepl.yml ]]; then
        DETECTED_ZREPL="y"
        log_info "Zrepl detected: yes"
    else
        DETECTED_ZREPL="n"
        log_info "Zrepl detected: no"
    fi

    # Detect username (first non-system user in /home, excluding root)
    for user_dir in /home/*/; do
        if [[ -d "$user_dir" ]]; then
            local user
            user=$(basename "$user_dir")
            if [[ "$user" != "root" && "$user" != "lost+found" ]]; then
                DETECTED_USER="$user"
                log_info "Detected user: $DETECTED_USER"
                break
            fi
        fi
    done

    if [[ -z "${DETECTED_USER:-}" ]]; then
        DETECTED_USER="packer"
        log_warn "Could not detect user, defaulting to: $DETECTED_USER"
    fi

    # Detect SecureBoot status
    if command -v sbctl >/dev/null 2>&1; then
        if sbctl status 2>/dev/null | grep -q "Enabled"; then
            DETECTED_SECUREBOOT="y"
            log_info "SecureBoot detected: yes"
        else
            DETECTED_SECUREBOOT="n"
            log_info "SecureBoot detected: no"
        fi
    else
        DETECTED_SECUREBOOT="n"
        log_info "SecureBoot detected: no (sbctl not installed)"
    fi

    # Detect if rescue dataset exists
    if zfs list "${DETECTED_POOL}/ROOT/${DETECTED_SUITE}_rescue_base" >/dev/null 2>&1; then
        DETECTED_RESCUE="y"
        log_info "Rescue dataset detected: yes"
    else
        DETECTED_RESCUE="n"
        log_info "Rescue dataset detected: no"
    fi

    # Detect swap configuration
    if zfs list "${DETECTED_POOL}/ROOT/swap" >/dev/null 2>&1; then
        DETECTED_SWAP_SIZE=$(zfs get -H -o value volsize "${DETECTED_POOL}/ROOT/swap" 2>/dev/null || echo "0")
        DETECTED_HIBERNATE="n"
        log_info "Swap zvol detected: yes"
    elif [[ -e /dev/disk/by-partlabel/SWAP_0 ]]; then
        DETECTED_SWAP_SIZE="300"
        DETECTED_HIBERNATE="y"
        log_info "Swap partition detected: yes (hibernation)"
    else
        DETECTED_SWAP_SIZE="0"
        DETECTED_HIBERNATE="n"
        log_info "Swap detected: no"
    fi

    # Detect Dropbear in ZFSBootMenu
    if ls /etc/zfsbootmenu/dracut.conf.d/*dropbear* >/dev/null 2>&1; then
        DETECTED_DROPBEAR="y"
        log_info "Dropbear in ZFSBootMenu detected: yes"
    else
        DETECTED_DROPBEAR="n"
        log_info "Dropbear in ZFSBootMenu detected: no"
    fi

    # Detect ZFSBootMenu binary type (LOCAL has config.yaml)
    if [[ -f /etc/zfsbootmenu/config.yaml ]]; then
        DETECTED_ZFSBOOTMENU_BINARY_TYPE="LOCAL"
        log_info "ZFSBootMenu binary type detected: LOCAL"
    else
        DETECTED_ZFSBOOTMENU_BINARY_TYPE="KERNEL"
        log_info "ZFSBootMenu binary type detected: KERNEL"
    fi
}

# Generate runtime vars file
generate_vars_file() {
    local vars_file="/tmp/goss-runtime-vars.yaml"
    
    cat > "$vars_file" <<EOF
# Auto-generated vars from run-validation.sh
poolname: ${DETECTED_POOL}
suite: ${DETECTED_SUITE}
username: ${DETECTED_USER}
discenc: ${DETECTED_ENC}
zrepl: ${DETECTED_ZREPL}
secureboot: ${DETECTED_SECUREBOOT}
rescue: ${DETECTED_RESCUE}
hibernate: ${DETECTED_HIBERNATE}
size_swap: ${DETECTED_SWAP_SIZE}
dropbear: ${DETECTED_DROPBEAR}
zfsbootmenu_binary_type: ${DETECTED_ZFSBOOTMENU_BINARY_TYPE}
EOF

    echo "$vars_file"
}

# Run validation tests
run_tests() {
    local gossfile="${TEST_DIR}/goss-smoke.yaml"
    local vars_file="${GOSS_VARS_FILE:-}"
    
    if [[ ! -f "$gossfile" ]]; then
        log_error "Goss test file not found: $gossfile"
        exit 1
    fi

    # If no vars file specified, generate one
    if [[ -z "$vars_file" ]]; then
        vars_file=$(generate_vars_file)
        log_info "Using auto-generated vars: $vars_file"
    else
        log_info "Using specified vars file: $vars_file"
    fi

    # Also check for variant-specific vars file
    local variant_vars="${TEST_DIR}/vars-${DETECTED_ENC}.yaml"
    if [[ -f "$variant_vars" ]]; then
        log_info "Found variant vars file: $variant_vars"
    fi

    log_info "Running goss validation..."
    log_info "Format: $GOSS_FORMAT"
    echo ""
    echo "=========================================="
    echo "VALIDATION RESULTS"
    echo "=========================================="
    echo ""

    # Build goss command
    local goss_cmd="$GOSS_BIN --gossfile $gossfile"
    
    # Add variant vars if exists
    if [[ -f "$variant_vars" ]]; then
        goss_cmd="$goss_cmd --vars $variant_vars"
    fi
    
    # Add runtime vars
    goss_cmd="$goss_cmd --vars $vars_file"
    
    # Run validation
    if $goss_cmd validate --format "$GOSS_FORMAT"; then
        echo ""
        echo "=========================================="
        log_info "✓ All validation tests passed!"
        echo "=========================================="
        return 0
    else
        echo ""
        echo "=========================================="
        log_error "✗ Some validation tests failed"
        echo "=========================================="
        return 1
    fi
}

# Main execution
main() {
    log_info "ZFS-root Validation Runner"
    log_info "=========================="
    echo ""
    log_info "VALIDATION_DIR = $VALIDATION_DIR"

    # check_root
    install_goss
    detect_config
    run_tests
}

# Handle command line args
case "${1:-}" in
    --help|-h)
        echo "ZFS-root Validation Runner"
        echo ""
        echo "Usage: $0 [--format FORMAT]"
        echo ""
        echo "Options:"
        echo "  --format FORMAT    Output format (documentation, json, tap, junit)"
        echo "  --help, -h         Show this help"
        echo ""
        echo "Environment Variables:"
        echo "  GOSS_FORMAT        Output format (default: documentation)"
        echo "  GOSS_VARS_FILE     Path to custom vars file"
        echo "  VALIDATION_DIR     Directory containing tests (default: /tmp/Validation)"
        exit 0
        ;;
    --format)
        GOSS_FORMAT="${2:-documentation}"
        shift 2
        ;;
esac

main "$@"
