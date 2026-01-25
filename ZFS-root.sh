#!/bin/bash

# https://www.osso.nl/blog/proxmox-virtio-blk-disk-by-id/
#
# Arch setup with encrypted zfs root and swap
# https://nwildner.com/posts/2025-09-03-zfs-setup/
#
# packer with virtio-scsi as disk_interface creates
# /dev/disk/by-id/scsi-0QWMU_QEMU_HARDDISK_drive0
#
# Manual packer run using docker as a non-local/CICD run
# Must do "packer init" first with the whole "init ZFS-root_local.pkr.hcl" to populate .packer.d/plugins
# The volume for /root/.cache/packer is for persistent cache of the ISO download
# Could do this as a local run with a volume pointing to the ISO location
#
# ❯ docker run --rm -it -v "$(pwd)":"${PWD}" -w "${PWD}" --privileged --cap-add=ALL -v "${PWD}/.packer.d":/root/.cache/packer -v /usr/share/OVMF:/usr/share/OVMF -e PACKER_PLUGIN_PATH="${PWD}/.packer.d/plugins" -e PACKER_LOG=1 halfwalker/docker-qemu build ZFS-root_local.pkr.hcl
#
# Running locally
# ❯ packer build -var-file=ZFS-root-packer_local.vars.hcl ZFS-root_local.pkr.hcl
#
# Sample cmd to run a VM with the resulting disk image - needs virtio-scsi-pci to get
# disk to show up in /dev/disk/by-id
# ❯ kvm -no-reboot -m 2048 -drive file=packer-zfsroot-2023-07-23-1754,format=qcow2,cache=none -device virtio-scsi-pci,id=scsi0

# LUKS
# https://fossies.org/linux/cryptsetup/docs/Keyring.txt

# https://hamy.io/post/0009/how-to-install-luks-encrypted-ubuntu-18.04.x-server-and-enable-remote-unlocking/#gsc.tab=0
# https://www.arminpech.de/2019/12/23/debian-unlock-luks-root-partition-remotely-by-ssh-using-dropbear/

# Single script to setup zfsbootmenu root-on-zfs with dracut and dropbear
# https://github.com/Sithuk/ubuntu-server-zfsbootmenu/blob/main/ubuntu_server_encrypted_root_zfs.sh

# >>>>>>>>>> ZFS native encryption <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# https://arstechnica.com/gadgets/2021/06/a-quick-start-guide-to-openzfs-native-encryption/
# https://talldanestale.dk/2020/04/06/zfs-and-homedir-encryption/
### Simple script to unlock home dataset etc. at boot
# https://gbyte.dev/blog/unlock-mount-several-zfs-datasets-boot-single-passphrase
# https://github.com/dynerose/Remote-unlock-native-ZFS

# NOTE: Intesting ideas
# https://blobfolio.com/2018/06/replace-grub2-with-systemd-boot-on-ubuntu-18-04/
# https://github.com/dyindude/ubuntu-zfs
# systemd-boot and systemd-boot-manager
#    https://forum.manjaro.org/t/manjaros-grub-probe-compatibility-with-zfs/127134/12
# dropbear remote unlocking
#    https://hamy.io/post/0009/how-to-install-luks-encrypted-ubuntu-18.04.x-server-and-enable-remote-unlocking/
# remote key via https https://github.com/stupidpupil/https-keyscript
# Also look into tang keyserver
# AWS keyserver for luks
#    https://icicimov.github.io/blog/server/LUKS-with-AWS-SSM-and-KMS-in-Systemd/

#
# This will set up a single-disk system with root-on-zfs, using
# bionic/18.04 or focal/20.04 or jammy/22.04 or noble/24.04.
#
# >>>>>>>>>> NOTE: This will totally overwrite the disk(s) chosen <<<<<<<<<<<<<
#
# 1) Boot an Ubuntu live cd to get a shell. Ubuntu live-server is a good choice.
# 2) Open a shell (ctrl-t) and become root (sudo -i)
# 3) Copy this script onto the box somehow - scp from somewhere
# 4) Make it executable (chmod +x ZFS-root.sh)
# 5) Run it (./ZFS-root.sh)
# 6) Add -d to enable set -x debugging (./ZFS-root.sh -d)
# 7) Add "-p" to run in a CI/CD pipeline using ZFS-root.conf.packerci
#
# It will ask a few questions (username, which disk, bionic/focal etc)
# and then fully install a minimal Ubuntu system. Depending on the choices
# several partitions and zfs datasets will be created.
#
# Part Name  Use
# ===========================================================================
#  1   BOOT  EFI partition, also has syslinux
#  2   SWAP  Only created if HIBERNATE is enabled (may be encrypted with LUKS)
#  3   ZFS   Main zfs pool (rpool) for full system (rpool/ROOT/bionic)
#
# Datasets created
# ================
# rpool/ROOT/bionic               Contains main system
# rpool/ROOT/bionic@base_install  Snapshot of install main system
# rpool/home                      Container for user directories
# rpool/home/<username>           Dataset for initial user
# rpool/home/root                 Dataset for root user
#
# One option is to enable LUKS full disk encryption. If HIBERNATE is enabled
# and a SWAP partition created, then that will be encrypted as well.
#
# NOTE: The HIBERNATE option will be disabled if the appropriate feature is not
# enabled in the power options of the system bios (/sys/power/state)
#
# NOTE: If installing under KVM, then the SCSI disk driver must be used,
#       not the virtio one. Otherwise the disks will not be linked into the
#       /dev/disk/by-id/ directory.

# Return codes from whiptail
# 0   OK in menu
# 1   Cancel in menu
# 255 Esc key hit

# -------------------------------------------------------------------------------------------------------
# Preflight - initial setup
preflight() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" 1>&2
        exit 1
    fi

    while getopts "dpc:" opt ; do
        case $opt in
            d)
                DEBUG=true
                ;;
            p)
                # Optional param for Packer config file - defaults to ZFS-root.conf.packerci below
                eval NEXT_OPT=\${$OPTIND}
                # Check if the next parameter exists and does not start with a dash (-)
                if [[ -n $NEXT_OPT ]] && [[ $NEXT_OPT != -* ]]; then
                    # If it's a valid argument, consume it and increment OPTIND
                    PACKERCI=$NEXT_OPT
                    OPTIND=$((OPTIND + 1))
                else
                    PACKERCI=false
                fi
                ;;
            c)
                CONFIG_FILE=$OPTARG
                ;;
            \?)
                echo "Invalid option: $OPTARG" >&2
                exit 1
                ;;
        esac
    done

    # [[ -v PACKERCI ]] && echo "Packer $PACKERCI" || echo "Packer was NOT set"
    # [[ -v CONFIG_FILE ]] && echo "Config file $CONFIG_FILE" || echo "No config file"
    # [[ -v DEBUG ]] && echo "Debug mode set" || echo "Debug mode NOT set"

    # Fugly logic ...
    #   -p          : Default to ZFS-root.conf.packerci
    #   -p <file>   : Use <file> for packer config
    if [[ -v PACKERCI ]] ; then
        if [[ -e ${PACKERCI} ]] ; then
            echo "Packer sourcing ${PACKERCI}"
            . ./${PACKERCI}
        elif [[ "${PACKERCI}" == false ]] && [[ -e ZFS-root.conf.packerci ]] ; then
            echo "Packer sourcing ZFS-root.conf.packerci"
            . ZFS-root.conf.packerci
        else
            echo "No valid Packer config file found"
            exit 1
        fi
    fi

    # Grab any possible pre-config settings in ZFS-root.conf or passed-in config file
    if [[ -v CONFIG_FILE ]] && [[ -e ${CONFIG_FILE} ]] ; then
        echo "Main sourcing ${CONFIG_FILE}"
        . ./${CONFIG_FILE}
    elif [[ -e ZFS-root.conf ]] ; then
        echo "Main sourcing ZFS-root.conf"
        . ZFS-root.conf
    else
        echo "No valid config file found"
        exit 1
    fi

    # ZFSBOOTMENU_REPO_TYPE - use the tagged git release or latest git clone
    # = TAGGED
    # = GIT
    [[ ! -v ZFSBOOTMENU_REPO_TYPE ]] && ZFSBOOTMENU_REPO_TYPE=TAGGED

    # ZFSBOOTMENU_CMDLINE - any additional cmdline options for zfsbootmenu
    # May need options to skip xhci-unbind - see ZFS-root.conf.example
    # See https://docs.zfsbootmenu.org/en/v3.0.x/man/zfsbootmenu.7.html
    [[ ! -v ZFSBOOTMENU_CMDLINE ]] && ZFSBOOTMENU_CMDLINE=""

    # For SOF binaries, default to 2025.05.1
    if [[ ! -v $SOF_VERSION ]] ; then
        SOF_VERSION=2025.05.1
    fi

    # No magenta overrides for whiptail dialogs please
    export NEWT_COLORS="none"

    # Build location - will be removed prior to build
    # NOTE: Can NOT have "zfs" in the name
    ZFSBUILD=/mnt/builder

    # Partition numbers of each partition
    PARTITION_BOOT=1
    PARTITION_SWAP=2
    PARTITION_DATA=3
    PARTITION_WIND=4
    PARTITION_RCVR=5

    # ZFS encryption options
    ZFSENC_ROOT_OPTIONS="-o encryption=aes-256-gcm -o keylocation=prompt -o keyformat=passphrase"
    # NOTE: for keyfile, put key in local /etc/zfs, then later copy to target /etc/zfs
    #       to be used for encrypting /home
    ZFSENC_HOME_OPTIONS="-o encryption=aes-256-gcm -o keylocation=file:///etc/zfs/zroot.homekey -o keyformat=passphrase"

    # Use zswap compressed page cache in front of swap ? https://wiki.archlinux.org/index.php/Zswap
    # Only used for swap partition (encrypted or not)
    USE_ZSWAP="zswap.enabled=1 zswap.compressor=lz4 zswap.max_pool_percent=25"
} # preflight()


# -------------------------------------------------------------------------------------------------------
# Query the user if we're wiping the system to start fresh, or just going to
# install/create a new ROOT dataset in an existing system
wipe_fresh() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    if [[ -v PACKERCI ]] ; then
        export WIPE_FRESH=y
    else
        if [[ ! -v WIPE_FRESH ]] ; then
            WIPE_FRESH=$(whiptail --title "Wipe system and install fresh ?" --yesno "Should this system be wiped completely for a fresh install ?\n\nNOTE: This will utterly wipe the selected disks\n      Be sure you're right." 11 65 \
        3>&1 1>&2 2>&3)
        RET=${?}
        [[ ${RET} = 0 ]] && WIPE_FRESH=y
        [[ ${RET} = 1 ]] && WIPE_FRESH=n
        fi
    fi

} # wipe_fresh()


# -------------------------------------------------------------------------------------------------------
# Query the user for any cacher (apt-cacher-ng for example)
setup_cacher() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"

    apt-get -qq update
    # We need libnss-mdns to resolve names like bondi.local etc.
    apt-get -qq --no-install-recommends --yes install libnss-mdns wget gpg

    # Check for a local apt-cacher-ng system - looking for these hosts
    # aptcacher.local
    # bondi.local
    # First see if PROXY is already set in ZFS-root.conf
    if [[ ! -v PROXY ]] ; then
        echo "Searching for local apt-cacher-ng proxy systems ..."
        PROXY=""
        for CACHER in bondi.local aptcacher.local ; do
            echo -n "... testing ${CACHER}"
            CACHER=$(ping -w 2 -c 1 ${CACHER} | grep "bytes from" | cut -d' ' -f4)
            if [ "${CACHER}" != "" ] ; then
                echo " - found !"
                PROXY="http://${CACHER}:3142/"
                break
            else
                echo " - not found :("
            fi
        done

        PROXY=$(whiptail --inputbox "Enter an apt proxy. Cancel or hit <esc> for no proxy" --title "APT proxy setup" 8 70 $PROXY 3>&1 1>&2 2>&3)
        RET=${?}
        (( RET )) && PROXY=
    fi # Check if PROXY is set already
    if [ "${PROXY}" ]; then
        # export http_proxy=${PROXY}
        # export ftp_proxy=${PROXY}
        # This is for apt-get
        echo "Acquire::http::proxy \"${PROXY}\";" > /etc/apt/apt.conf.d/03proxy
    fi # PROXY

    apt-get -qq update
    apt-get -qq --no-install-recommends --yes install software-properties-common
    apt-add-repository -y universe
    # Need universe for debconf-utils
    apt-get -qq --no-install-recommends --yes install debconf-utils
} # setup_cacher()


# -------------------------------------------------------------------------------------------------------
# Query the user for general settings
query_user() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Get userid and full name of main user
    # First see if USERNAME or UCOMMENT are already set in ZFS-root.conf
    if [[ ! -v USERNAME ]] || [[ ! -v UCOMMENT ]] ; then
        [[ ! -v USERNAME ]] && USERNAME=george
        [[ ! -v UCOMMENT ]] && UCOMMENT="George of the Jungle"
        USERINFO=$(whiptail --inputbox "Enter username (login id) and full name of user\nAs in <username> <space> <First and Last name>\n\nlogin full name here\n|---| |------------ - - -  -  -" --title "User information" 11 70 "$USERNAME $UCOMMENT" 3>&1 1>&2 2>&3)
        RET=${?}
        [[ ${RET} = 1 ]] && exit 1
        USERNAME=$(echo "$USERINFO" | cut -d' ' -f1)
        UCOMMENT=$(echo "$USERINFO" | cut -d' ' -f2-)
    fi # Check if USERNAME/UCOMMENT set

    # Get password, confirm and loop until confirmation OK
    if [[ ! -v UPASSWORD ]]; then
        DONE=false
        until ${DONE} ; do
            PW1=$(whiptail --passwordbox "Please enter a password for user $USERNAME" 8 70 --title "User password" 3>&1 1>&2 2>&3)
            PW2=$(whiptail --passwordbox "Please re-enter the password to confirm" 8 70 --title "User password confirmation" 3>&1 1>&2 2>&3)
            [ "$PW1" = "$PW2" ] && DONE=true
        done
        UPASSWORD="$PW1"
    fi # Check if UPASSWORD already set

    # Hostname - cancel or blank name will exit
    if [[ ! -v MYHOSTNAME ]] ; then
        MYHOSTNAME="test"
        MYHOSTNAME=$(whiptail --inputbox "Enter hostname to be used for new system. This name may also be used for the main ZFS poolname." --title "Hostname for new system." 8 70 "$MYHOSTNAME" 3>&1 1>&2 2>&3)
        RET=${?}
        (( RET )) && MYHOSTNAME=
        if [ ! "${MYHOSTNAME}" ]; then
            echo "Must have a hostname"
            exit 1
        fi
    fi # Check if MYHOSTNAME already set

    if [[ ! -v POOLNAME ]] ; then
        POOLNAME=${MYHOSTNAME}
        POOLNAME=$(whiptail --inputbox "Enter poolname to use for main system - defaults to hostname" --title "ZFS main poolname" 8 70 "$POOLNAME" 3>&1 1>&2 2>&3)
        RET=${?}
        (( RET )) && POOLNAME=
        if [ ! "${POOLNAME}" ]; then
            echo "Must have a ZFS poolname"
            exit 1
        fi
    fi # Check if POOLNAME already set
} # query_user()


# -------------------------------------------------------------------------------------------------------
# Select which disk(s) to install to
# Only called when WIPE_FRESH = y
select_disks() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    #
    # If script was started with one parameter "packerci" then we're running under CI/CD
    # and using packer to build an image via qemu. That means a single disk /dev/vda
    # We need to create the symlink in /dev/disk/by-id for it
    #
    if [[ -v PACKERCI ]] ; then
        echo "Setting single disk scsi-0QEMU_QEMU_HARDDISK_drive0"
        readarray -t zfsdisks < <(echo "scsi-0QEMU_QEMU_HARDDISK_drive0")
    else
        # Set main disk here - be sure to include the FULL path
        # Get list of disks, ask user which one to install to
        # Ignore cdrom etc.  Limit disk name length to avoid menu uglyness
        # readarray -t disks < <(ls -l /dev/disk/by-id | egrep -v '(CDROM|CDRW|-ROM|CDDVD|-part|md-|dm-|wwn-)' | sort -t '/' -k3 | tr -s " " | cut -d' ' -f9 | cut -c -58 | sed '/^$/d')
        readarray -t disks < <(find /dev/disk/by-id | grep -E -v '(CDROM|CDRW|-ROM|CDDVD|-part|md-|dm-|wwn-)' | cut -d'/' -f5 | sed '/^$/d' | sort)

        # If no disks available (kvm needs to use scsi, not virtio) then error out
        if [ ${#disks[@]} -eq 0 ] ; then
            whiptail --title "No disks available in /dev/disk/by-id" --msgbox "No valid disk links were found in /dev/disk/by-id - ensure your target disk has a link in that directory.\n\nKVM/qemu VMs need to use the SCSI storage driver, not the default virtio one (which does not create links in /dev/disk/by-id)" 12 70
            exit 1
        fi

        TMPFILE=$(mktemp)
        # Find longest disk name
        m=-1
        for disk in "${disks[@]}"
        do
           if [ ${#disk} -gt $m ]
           then
              m=${#disk}
           fi
        done

        # Set dialog box size to num disks
        list_height=$(( ${#disks[@]} + 1 ))
        box_height=$(( ${#disks[@]} + 8 ))
        box_width=$(( m + 26 ))

        DONE=false
        until ${DONE} ; do
            whiptail --title "List of disks" --separate-output --checklist --noitem \
                "Choose disk(s) to install to" ${box_height} ${box_width} ${list_height} \
                $(for disk in $(seq 0 $(( ${#disks[@]}-1)) ) ; do echo "${disks[${disk}]}" OFF ; done) 2> "${TMPFILE}"
            RET=${?}
            [[ ${RET} = 1 ]] && exit 1

            readarray -t zfsdisks < <(cat "${TMPFILE}")
            if [ ${#zfsdisks[@]} != 0 ] ; then
                DONE=true
            fi
        done
    fi # Check for packerci

    # Single disk can only be "single"
    if [ ${#zfsdisks[@]} -eq 1 ] ; then
        RAIDLEVEL="single"
    fi

    # Check if raid level already set in ZFS-root.conf
    if [[ ! -v RAIDLEVEL ]] ; then
        #_# DISK="/dev/disk/by-id/${DISK}"
        if [ ${#zfsdisks[@]} -gt 1 ] ; then
            RAIDLEVEL=$(whiptail --title "ZPOOL raid level" --radiolist "Select ZPOOL raid level" 12 60 5 \
                single "No raid, just single disks as vdevs" OFF \
                mirror "All disks mirrored" OFF \
                raidz1 "All disks in raidz1 format" OFF \
                raidz2 "All disks in raidz2 format" OFF \
                raidz3 "All disks in raidz3 format" OFF 3>&1 1>&2 2>&3)
            RET=${?}
            [[ ${RET} = 1 ]] && exit 1
        fi
    fi # Check RAIDLEVEL already set

    # We use ${RAIDLEVEL} to set zpool raid level - just vdevs means that should be blank
    if [ "${RAIDLEVEL}" = "single" ] ; then RAIDLEVEL= ; fi
} # select_disks()


# -------------------------------------------------------------------------------------------------------
# Query the user for any disk encryption
# Only called when WIPE_FRESH = y
select_encryption() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    if [ "${WIPE_FRESH}" == "y" ] ; then
        if [[ ! -v DISCENC ]] ; then
            DISCENC=$(whiptail --title "Select disk encryption" --radiolist "Choose which (if any) disk encryption to use" 11 60 4 \
                NOENC "No disk encryption" ON \
                ZFSENC "Enable ZFS dataset encryption" OFF \
                LUKS "Enable LUKS full disk encryption" OFF \
                3>&1 1>&2 2>&3)
            RET=${?}
            [[ ${RET} = 1 ]] && exit 1
        fi # Check DISCENC already set
    else
        # NOT wiping fresh, so LUKS doesn't make sense
        if [[ ! -v DISCENC ]] ; then
            DISCENC=$(whiptail --title "Encryption ZFS datasets" --radiolist "Choose whether to encrypt the new ROOT dataset" 11 60 4 \
                NOENC "No disk encryption" ON \
                ZFSENC "Enable ZFS dataset encryption" OFF \
                3>&1 1>&2 2>&3)
            RET=${?}
            [[ ${RET} = 1 ]] && exit 1
        fi # Check DISCENC already set
    fi

    # ZFSBOOTMENU_BINARY_TYPE - use a downloaded binary or build locally
    # = KERNEL (default - use vmlinuz/initrd pair from downloaded binary)
    # = EFI    (use EFI binary - NOTE: precludes syslinux from working)
    # = LOCAL  (built locally)
    #
    # NOTE: If Dropbear is required for remote unlocking of LUKS or ZFS enecryption
    #       then this will be forced to LOCAL below in the Dropbear config section.
    #       This is because Dropbear must be included in the initramfs for zfsbootmenu.
    #       Same for LUKS encryption since we need the early-stage script to unlock
    [[ ! -v ZFSBOOTMENU_BINARY_TYPE ]] && ZFSBOOTMENU_BINARY_TYPE=KERNEL

    # If encryption enabled, need a passphrase
    case ${DISCENC} in
        LUKS|ZFSENC)
            if [[ ! -v PASSPHRASE ]] ; then
                DONE=false
                until ${DONE} ; do
                    PW1=$(whiptail --passwordbox "Please enter a good long encryption passphrase" 8 70 --title "Encryption passphrase" 3>&1 1>&2 2>&3)
                    PW2=$(whiptail --passwordbox "Please re-enter the encryption passphrase" 8 70 --title "Encryption passphrase confirmation" 3>&1 1>&2 2>&3)
                    [ "$PW1" = "$PW2" ] && DONE=true
                done
                PASSPHRASE="$PW1"
            fi # If PASSPHRASE not already set in ZFS-root.conf

            # retcode 0 = YES, 1 = NO
            if [[ ! -v DROPBEAR ]] ; then
                DROPBEAR=$(whiptail --title "Enable Dropbear ?" --yesno "Should Dropbear be enabled for remote unlocking of encrypted disks ?\n\nNOTE: Dropbear requires use of ZFSBOOTMENU_BINARY_TYPE as LOCAL, so it can be built locally" 12 60 \
                3>&1 1>&2 2>&3)
                RET=${?}
                [[ ${RET} = 0 ]] && DROPBEAR=y
                [[ ${RET} = 1 ]] && DROPBEAR=n
            fi
            # If we have encryption and want Dropbear, then we HAVE to have the LOCAL
            # version of zfsbootmenu, so we can rebuild the zfsbootmenu initramfs to
            # include Dropbear.  If DISCENC is LUKS then we need LOCAL as well, so we
            # get the early-stage script to unlock LUKS-encrypted partitions.
            if [ "${DROPBEAR}" == "y" ] || [ "${DISCENC}" == "LUKS" ] ; then
                ZFSBOOTMENU_BINARY_TYPE=LOCAL
            fi
            ;;

        NOENC)
            # Default Dropbear to NO
            DROPBEAR=n
            ;;
    esac
} # select_encryption()


# -------------------------------------------------------------------------------------------------------
# Select install options
query_install_options() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # We check /sys/power/state - if no "disk" in there, then HIBERNATE is disabled
    grep disk < /sys/power/state > /dev/null
    HIBERNATE_AVAIL=${?}
    # Force Hibernate to n if not available, overriding anything in ZFS-root.conf
    [ ${HIBERNATE_AVAIL} -ne 0 ] && HIBERNATE=n

    #
    # Slightly fugly - have to check if ANY of these are not set
    #
    if [[ ! -v ZREPL ]] || [[ ! -v RESCUE ]] || [[ ! -v GOOGLE ]] || [[ ! -v HWE ]] || [[ ! -v HIBERNATE ]] || [[ ! -v DELAY ]] || [[ ! -v SOF ]] || [[ ! -v GNOME ]] || [[ ! -v KDE ]] || [[ ! -v NEON ]] || [[ ! -v XFCE ]] ; then
        # Hibernate can only resume from a single disk, and currently not available for ZFS encryption
        if [ "${DISCENC}" == "ZFSENC" ] || [ ${#zfsdisks[@]} -gt 1 ] || [ ${HIBERNATE_AVAIL} -ne 0 ] ; then
            # Set basic options for install - ZFSENC so no Hibernate available (yet)
            whiptail --title "Set options to install" --separate-output --checklist "Choose options\n\nNOTE: 18.04 HWE kernel requires pool attribute dnodesize=legacy" 22 89 11 \
                RESCUE "Create rescue dataset by cloning initial install" OFF \
                GOOGLE "Add google authenticator via pam for ssh logins" OFF \
                HWE "Install Hardware Enablement kernel" OFF \
                ZREPL "Install Zrepl zfs snapshot manager" OFF \
                DELAY "Add delay before importing root pool - for many-disk systems" OFF \
                SOF "Install Sound Open Firmware binaries ${SOF_VERSION} (for some laptops)" OFF \
                GNOME "Install Ubuntu Gnome desktop" OFF \
                XFCE "Install Ubuntu xfce4 desktop with goodies" OFF \
                KDE "Install Ubuntu KDE Plasma desktop" OFF \
                NEON "Install Neon KDE Plasma desktop" OFF 2>"${TMPFILE}"
        else
            # Set basic options for install - ZFSENC so no Hibernate available (yet)
            whiptail --title "Set options to install" --separate-output --checklist "Choose options\n\nNOTE: 18.04 HWE kernel requires pool attribute dnodesize=legacy" 23 89 12 \
                RESCUE "Create rescue dataset by cloning initial install" OFF \
                GOOGLE "Add google authenticator via pam for ssh logins" OFF \
                HWE "Install Hardware Enablement kernel" OFF \
                ZREPL "Install Zrepl zfs snapshot manager" OFF \
                HIBERNATE "Enable swap partition for hibernation" OFF \
                DELAY "Add delay before importing root pool - for many-disk systems" OFF \
                SOF "Install Sound Open Firmware binaries ${SOF_VERSION} (for some laptops)" OFF \
                GNOME "Install Ubuntu Gnome desktop" OFF \
                XFCE "Install Ubuntu xfce4 desktop with goodies" OFF \
                KDE "Install Ubuntu KDE Plasma desktop" OFF \
                NEON "Install Neon KDE Plasma desktop" OFF 2>"${TMPFILE}"
        fi
        RET=${?}
        [[ ${RET} = 1 ]] && exit 1

        # Set any selected options to 'y'
        while read -r TODO ; do
            eval "${TODO}"='y'
        done < "${TMPFILE}"

        # Any options not enabled in the basic options menu we now set to 'n'
        for option in ZREPL RESCUE GNOME XFCE NEON KDE HWE HIBERNATE DELAY SOF GOOGLE; do
            [ ${!option} ] || eval "${option}"='n'
        done
    fi # Check ALL options from ZFS-root.conf
} # query_install_options()


# -------------------------------------------------------------------------------------------------------
# Possibly offer Nvidia driver install
query_nvidia() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # See if we need to install Nvidia drivers, notify if so
    # shellcheck disable=SC2046,SC2086  # Don't need quotes or double-quotes
    if [[ ! -v NVIDIA ]] ; then
        NVIDIA=none
        if [ "${GNOME}" = "y" ] || [ "${KDE}" = "y" ] || [ "${NEON}" = "y" ] || [ "${XFCE}" = "y" ] ; then
            if [ $(lspci | grep -ic nvidia) -gt 0 ] ; then
                # Installing Nvidia PPA here just so we can search for versions
                apt-add-repository --yes --update ppa:graphics-drivers/ppa
                NVIDIA_LATEST=$(apt-cache search nvidia-driver- | cut -d ' ' -f1 | grep -e "nvidia-driver-...$" | cut -d'-' -f3 | sort | tail -1)
                NVIDIA=$(whiptail --title "Nvidia Hardware detected - install latest driver ?" --radiolist "Gnome/KDE/NEON was selected, and Nvidia graphics HW was detected on this system.  The ppa:graphics-drivers/ppa repo could be installed in order to get the binary Nvidia driver\n\nNOTE: Be sure to select the correct driver - the latest (${NVIDIA_LATEST}) may not support older legacy HW.  See\n\nhttps://www.nvidia.com/en-us/drivers/unix/legacy-gpu/\n\nfor more information on legacy HW.  It is safe to select NONE if you are unsure.  You can always install the appropriate driver later via Additional Drivers" 22 70 4 \
                    ${NVIDIA_LATEST} "Latest ${NVIDIA_LATEST}" OFF \
                    470    "Legacy 470 driver" OFF \
                    390    "Legacy 390 driver" OFF \
                    none   "No Nvidia driver" ON \
                    3>&1 1>&2 2>&3)
                RET=${?}
                [[ ${RET} = 1 ]] && exit 1
            fi
        fi
    fi
} # query_nvidia()


# -------------------------------------------------------------------------------------------------------
# Query for Google Authenticator, create secret for install
query_google_auth() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Show google authenticator info - file in /root/google_auth.txt is like
    # AGNGG2UOIDJXDJNZ
    # "RATE_LIMIT 3 30
    # " WINDOW_SIZE 3
    # " DISALLOW_REUSE
    # " TOTP_AUTH
    # 75667428
    # 93553495
    # 65484719
    # 23383624
    # 28747791
    if [ "${GOOGLE}" = "y" ] ; then
        apt-get -qq --no-install-recommends --yes install python3-qrcode libpam-google-authenticator qrencode
        # Generate a google auth config
        google-authenticator --time-based --disallow-reuse --label=${MYHOSTNAME} --qr-mode=UTF8 --rate-limit=3 --rate-time=30 --secret=/tmp/google_auth.txt --window-size=3 --force --quiet
        # Grab secret to build otpauth line below
        GOOGLE_SECRET=$(head -1 /tmp/google_auth.txt)

        # Have to tell whiptail library newt to use black/white text, otherwise QR code
        # is inverted and Authy can't read it
        # Set issuer to Ubuntu so we get a nice Ubuntu logo for the Authy secret
        export NEWT_COLORS='white,black'
    # shellcheck disable=SC2086  # Don't need quotes
    # shellcheck disable=SC1132  # & is part of the secret inside quotes
    # shellcheck disable=SC2034  # issuer is NOT a shell variable
        whiptail --title "Google Authenticator QR code and config" --msgbox "Config for ${USERNAME} is in /home/${USERNAME}/.google_authenticator\n\nBe sure to save the 5 emergency codes below\n\n$(cat /tmp/google_auth.txt)\n\nQR Code for use with OTP application (Authy etc.)\notpauth://totp/${MYHOSTNAME}.local:${USERNAME}?secret=${GOOGLE_SECRET}&Issuer=Ubuntu\n\n$(qrencode -m 3 -t UTF8 otpauth://totp/${MYHOSTNAME}.local:${USERNAME}?secret=${GOOGLE_SECRET}&issuer=Ubuntu)" 45 83
        RET=${?}
        [[ ${RET} = 1 ]] && exit 1
        export NEWT_COLORS="none"
    fi
} # query_google_auth()


# -------------------------------------------------------------------------------------------------------
# Query for any additional SSH keys to add to authorized_keys
query_ssh_auth() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # SSH authorized keys from github for dropbear and ssh
    if [[ ! -v AUTHKEYS ]] ; then
        AUTHKEYS=$(whiptail --inputbox "Dropbear and ssh need authorized ssh pubkeys to allow access to the server. Please enter any github users to pull ssh pubkeys from.  none means no keys to install\n\nDropbear is used for remote unlocking of disk encryption\n\n      ssh -p 222 root@<ip addr>" --title "SSH pubkeys for ssh and dropbear" 13 70 $(echo none) 3>&1 1>&2 2>&3)
        RET=${?}
        [[ ${RET} = 1 ]] && exit 1
        (( RET )) && AUTHKEYS=none
    fi # Check for github user ssh keys in AUTHKEYS

    # If it's NOT a ZFS encryption setup, then clear out the ZFSENC_ROOT_OPTIONS variable
    if [ "${DISCENC}" != "ZFSENC" ] ; then
        ZFSENC_ROOT_OPTIONS=""
        ZFSENC_HOME_OPTIONS=""
    fi
} # query_ssh_auth()


# -------------------------------------------------------------------------------------------------------
# Query for any swap usage, determine proper size for hibernation
query_swap() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Swap size - if HIBERNATE enabled then this will be an actual disk partition.
    # If DISCENC == LUKS then partition will be encrypted.  If SIZE_SWAP is not
    # defined here, then will be calculated to accommodate memory size (plus fudge factor).
    if [[ ! -v SIZE_SWAP ]] ; then
        # shellcheck disable=SC2002  # Using cat is clearer to understand
        MEMTOTAL=$(cat /proc/meminfo | grep -F MemTotal | tr -s ' ' | cut -d' ' -f2)
        SIZE_SWAP=$(( (MEMTOTAL + 20480) / 1024 ))
        # We MUST have a swap partition of at least ram size if HIBERNATE is enabled
        # So don't even prompt the user for a size. Her own silly fault if it's
        # enabled but she doesn't want a swap partition
        if [ "${HIBERNATE}" = "n" ] ; then
            SIZE_SWAP=$(whiptail --inputbox "If HIBERNATE enabled then this will be a disk partition otherwise it will be a regular ZFS dataset. If LUKS enabled then the partition will be encrypted.\nIf SWAP size not set here (left blank), then it will be calculated to accommodate memory size. Set to zero (0) to disable swap.\n\nSize of swap space in megabytes (default is calculated value)\nSet to zero (0) to disable swap" \
            --title "SWAP size" 15 70 $(echo $SIZE_SWAP) 3>&1 1>&2 2>&3)
            RET=${?}
            [[ ${RET} = 1 ]] && exit 1
        fi
    fi # Check for Swap size in ZFS-root.conf
} # query_swap()


# -------------------------------------------------------------------------------------------------------
# Query for which Ubuntu suite to install (plucky, noble, etc)
query_suite() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Suite to install - bionic focal jammy noble
    if [[ ! -v SUITE ]] ; then
        SUITE=$(whiptail --title "Select Ubuntu distribtion" --radiolist "Choose distro" 15 42 8 \
            questing "25.10 Questing Quokka" OFF \
            plucky "25.04 Plucky Puffin" OFF \
            noble "24.04 Noble Numbat" ON \
            jammy "22.04 Jammy Jellyfish" OFF \
            focal "20.04 Focal Fossa" OFF \
            bionic "18.04 Bionic Beaver" OFF \
            3>&1 1>&2 2>&3)
        RET=${?}
        [[ ${RET} = 1 ]] && exit 1
    fi # Check for Ubuntu suite to install

    #
    # TODO: Make use of SUITE_EXTRAS maybe
    #
    case ${SUITE} in
        questing)
            SUITE_NUM="25.10"
            SUITE_EXTRAS="netplan.io expect"
            SUITE_BOOTSTRAP="wget,whois,rsync,gdisk,netplan.io,gpg-agent"
            # Install HWE packages - set to blank or to "-hwe-25.04"
            # Gets tacked on to various packages below
            # TODO: No HWE packages for 25.04 yet - use this when/if available
            # [ "${HWE}" = "y" ] && HWE="-hwe-${SUITE_NUM}" || HWE=
            HWE=
            # Specific zpool features available in jammy
            SUITE_ROOT_POOL="-O dnodesize=auto"
            ;;
        plucky)
            SUITE_NUM="25.04"
            SUITE_EXTRAS="netplan.io expect"
            SUITE_BOOTSTRAP="wget,whois,rsync,gdisk,netplan.io,gpg-agent"
            # Install HWE packages - set to blank or to "-hwe-25.04"
            # Gets tacked on to various packages below
            # TODO: No HWE packages for 25.04 yet - use this when/if available
            # [ "${HWE}" = "y" ] && HWE="-hwe-${SUITE_NUM}" || HWE=
            HWE=
            # Specific zpool features available in jammy
            SUITE_ROOT_POOL="-O dnodesize=auto"
            ;;
        noble)
            SUITE_NUM="24.04"
            SUITE_EXTRAS="netplan.io expect"
            SUITE_BOOTSTRAP="wget,whois,rsync,gdisk,netplan.io,gpg-agent"
            # Install HWE packages - set to blank or to "-hwe-24.04"
            # Gets tacked on to various packages below
            [ "${HWE}" = "y" ] && HWE="-hwe-${SUITE_NUM}" || HWE=
            # Specific zpool features available in jammy
            SUITE_ROOT_POOL="-O dnodesize=auto"
            ;;
        jammy)
            SUITE_NUM="22.04"
            SUITE_EXTRAS="netplan.io expect"
            SUITE_BOOTSTRAP="wget,whois,rsync,gdisk,netplan.io,gpg-agent"
            # Install HWE packages - set to blank or to "-hwe-22.04"
            # Gets tacked on to various packages below
            [ "${HWE}" = "y" ] && HWE="-hwe-${SUITE_NUM}" || HWE=
            # Specific zpool features available in jammy
            SUITE_ROOT_POOL="-O dnodesize=auto"
            ;;
        focal)
            SUITE_NUM="20.04"
            SUITE_EXTRAS="netplan.io expect"
            SUITE_BOOTSTRAP="wget,whois,rsync,gdisk,netplan.io"
            # Install HWE packages - set to blank or to "-hwe-20.04"
            # Gets tacked on to various packages below
            [ "${HWE}" = "y" ] && HWE="-hwe-${SUITE_NUM}" || HWE=
            # Specific zpool features available in focal
            SUITE_ROOT_POOL="-O dnodesize=auto"
            ;;
        bionic)
            SUITE_NUM="18.04"
            SUITE_EXTRAS="netplan.io expect"
            SUITE_BOOTSTRAP="wget,whois,rsync,gdisk,netplan.io"
            # Install HWE packages - set to blank or to "-hwe-18.04"
            # Gets tacked on to various packages below
            [ "${HWE}" = "y" ] && HWE="-hwe-${SUITE_NUM}" || HWE=
            # Specific zpool features available in bionic
            SUITE_ROOT_POOL="-O dnodesize=legacy"
            ;;
        # Default to focal 24.04
        *)
            SUITE_NUM="24.04"
            SUITE_EXTRAS="netplan.io expect"
            SUITE_BOOTSTRAP="wget,whois,rsync,gdisk,netplan.io"
            # Install HWE packages - set to blank or to "-hwe-24.04"
            # Gets tacked on to various packages below
            [ "${HWE}" = "y" ] && HWE="-hwe-${SUITE_NUM}" || HWE=
            # Specific zpool features available in focal
            SUITE_ROOT_POOL="-O dnodesize=auto"
            ;;
    esac
} # query_suite()


# -------------------------------------------------------------------------------------------------------
# Determine if SecureBoot may be set up.  Uses sbctl which is only (currently) available for noble 24.04
# Later may clone the repo and build sbctl locally
# Only called when WIPE_FRESH = y
# Local building requires golang asciidoc-base pkgconf pkgconf-bin libpcsclite-dev
# NOTE: 'sbctl verify' does not work - fails with 'failed to find EFI system partition' due to ESP
#       being on a mdadm device for multiple boot devices
query_secureboot() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"

    # To build locally need libpcsclite-dev libpcsclite1 golang-go sbsigntool
    #   go install github.com/foxboron/sbctl/cmd/sbctl@latest
    #   mv go/bin/sbctl /usr/local/bin

    # If UEFI SecureBoot should be enabled - NOTE: only available for noble/24.04
    if [[ ! -v SECUREBOOT || "$SECUREBOOT" != "n" ]]; then
        if [[ -d /sys/firmware/efi && "${SUITE}" == "noble" ]] ; then
            # Create apt sources for sbctl
            curl -fsSL https://download.opensuse.org/repositories/home:jloeser:secureboot/xUbuntu_${SUITE_NUM}/Release.key | gpg --dearmor | sudo tee /usr/share/keyrings/secureboot.gpg > /dev/null

            # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
            cat > /etc/apt/sources.list.d/secureboot.sources <<- EOF
			X-Repolib-Name: SecureBoot
			Types: deb
			URIs: http://download.opensuse.org/repositories/home:/jloeser:/secureboot/xUbuntu_${SUITE_NUM}
			Signed-By: /usr/share/keyrings/secureboot.gpg
			Suites: /
			Enabled: yes
			Architectures: amd64
			EOF

            apt-get -qq update
            apt-get -qq --yes --no-install-recommends install systemd-boot-efi
            apt-get -qq --yes --no-install-recommends install sbctl jq

            # Are we in setup mode for SecureBoot ?
            SETUPMODE=$(sbctl status --json | jq '.setup_mode')
            if [ "${SETUPMODE}" == "true" ] ; then
                if [[ ! -v SECUREBOOT ]] ; then
                    SECUREBOOT=$(whiptail --title "UEFI SecureBoot is available" --yesno "Should UEFI SecureBoot be enabled ?" 8 60 \
                    3>&1 1>&2 2>&3)
                    RET=${?}
                    [[ ${RET} = 0 ]] && SECUREBOOT=y
                    [[ ${RET} = 1 ]] && SECUREBOOT=n
                fi
            else
                # Show current SecureBoot config, set SECUREBOOT var to n so we don't try to install in the chroot
                SBCTL_STATUS=$(sbctl status)
                whiptail --title "System UEFI not in setup mode" --msgbox "SecureBoot config in bios must be in setup mode\n\nFor VirtualBox delete the .nvram file\nFor other systems see the bios config\n\n${SBCTL_STATUS}" 17 56
                SECUREBOOT=n
            fi
        else
            # No /sys/firmware/efi means no UEFI means no SecureBoot
            SECUREBOOT=n
        fi

        # If SecureBoot automatic signing of rEFInd and ZFSBootMenu .efi bundles should be enabled
        if [ "${SECUREBOOT}" == "y" ] ; then
            if [[ ! -v AUTOSIGN ]] ; then
                AUTOSIGN=$(whiptail --title "Enable SecureBoot auto-signing" --yesno "Should systemd PATH watches be enabled to allow auto-signing of rEFInd and ZFSBootMenu ?\n\nNOTE: Auto-signing means ANY change to refind_x64.efi or zfsbootmenu.efi (or kernel/initramfs) will be signed, regardless of who/what made the changes.\n\nWithout auto-signing YOU must manage the signing - forgetting or mistakes can lead to the system being unbootable.  Signing is managed via the sbctl package." 17 60 3>&1 1>&2 2>&3)
            fi
        else
            AUTOSIGN=n
        fi
    fi # checking SECUREBOOT var
} # query_secureboot()


# -------------------------------------------------------------------------------------------------------
# Show what we're about to install
show_options() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    #
    # If script was started with one parameter "packerci" then we're running under CI/CD
    # and using packer to build an image via qemu. That means a single disk /dev/vda was
    # selected above and we do not want to pause here for
    #
    if [ "${WIPE_FRESH}" == "y" ] ; then
        box_height=$(( ${#zfsdisks[@]} + 31 ))
        # shellcheck disable=SC2086,SC2116
        whiptail --title "WIPING DISK(s) - Summary of install options" --msgbox "These are the options we're about to install with :\n\n \
        Proxy $([ ${PROXY} ] && echo ${PROXY} || echo None)\n \
        $(echo $SUITE $SUITE_NUM) $([ ${HWE} ] && echo WITH || echo without) $(echo hwe kernel ${HWE})\n \
        Disk $(for disk in $(seq 0 $(( ${#zfsdisks[@]}-1)) ) ; do \
          if [ ${disk} -ne 0 ] ; then echo -n "              " ; fi ; echo ${zfsdisks[${disk}]} ; done)\n \
        Raid $([ ${RAIDLEVEL} ] && echo ${RAIDLEVEL} || echo vdevs)\n \
        Hostname   = $(echo $MYHOSTNAME)\n \
        Host keys  = $([[ -v HOST_RSA_KEY || -v HOST_ECDSA_KEY || -v HOST_ED25519_KEY ]] && echo Pre-defined || echo Generate new)\n \
        Poolname   = $(echo $POOLNAME)\n \
        User       = $(echo $USERNAME $UCOMMENT)\n\n \
        SECUREBOOT = $SECUREBOOT  : Enable UEFI SecureBoot\n \
        AUTOSIGN   = ${AUTOSIGN}  : Enable auto-signing of bootable .efi bundles\n \
        RESCUE     = $(echo $RESCUE)  : Create rescue dataset by cloning install\n \
        DELAY      = $(echo $DELAY)  : Enable delay before importing zpool\n \
        ZREPL      = $(echo $ZREPL)  : Install Zrepl zfs snapshot manager\n \
        GOOGLE     = $(echo $GOOGLE)  : Install google authenticator\n \
        GNOME      = $(echo $GNOME)  : Install Ubuntu Gnome desktop\n \
        XFCE       = $(echo $XFCE)  : Install Ubuntu XFCE4 desktop\n \
        KDE        = $(echo $KDE)  : Install Ubuntu KDE Plasma desktop\n \
        NEON       = $(echo $NEON)  : Install Neon KDE Plasma desktop\n \
        NVIDIA     = $(echo $NVIDIA)  : Install Nvidia drivers\n \
        SOF        = $(echo $SOF)  : Install Sound Open Firmware ${SOF_VERSION} binaries\n \
        HIBERNATE  = $(echo $HIBERNATE)  : Enable SWAP disk partition for hibernation\n \
        DISCENC    = $(echo $DISCENC)  : Enable disk encryption (No, LUKS, ZFS)\n \
        DROPBEAR   = $(echo $DROPBEAR)  : Enable Dropbear unlocking of encrypted disks\n \
        Swap size  = $(echo $SIZE_SWAP)M $([ ${SIZE_SWAP} -eq 0 ] && echo ': DISABLED')\n" \
        ${box_height} 79
        RET=${?}
        [[ ${RET} = 1 ]] && exit 1
    else
        # Not wiping fresh, so no need for Disk, Raid, Secureboot, Autosign, Hibernate
        box_height=$(( ${#zfsdisks[@]} + 26 ))
        # shellcheck disable=SC2086,SC2116
        whiptail --title "New dataset - Summary of install options" --msgbox "These are the options we're about to install with :\n\n \
        Proxy $([ ${PROXY} ] && echo ${PROXY} || echo None)\n \
        $(echo $SUITE $SUITE_NUM) $([ ${HWE} ] && echo WITH || echo without) $(echo hwe kernel ${HWE})\n \
        Hostname   = $(echo $MYHOSTNAME)\n \
        Host keys  = $([[ -v HOST_RSA_KEY || -v HOST_ECDSA_KEY || -v HOST_ED25519_KEY ]] && echo Pre-defined || echo Generate new)\n \
        Poolname   = $(echo $POOLNAME)\n \
        User       = $(echo $USERNAME $UCOMMENT)\n\n \
        RESCUE     = $(echo $RESCUE)  : Create rescue dataset by cloning install\n \
        DELAY      = $(echo $DELAY)  : Enable delay before importing zpool\n \
        ZREPL      = $(echo $ZREPL)  : Install Zrepl zfs snapshot manager\n \
        GOOGLE     = $(echo $GOOGLE)  : Install google authenticator\n \
        GNOME      = $(echo $GNOME)  : Install Ubuntu Gnome desktop\n \
        XFCE       = $(echo $XFCE)  : Install Ubuntu XFCE4 desktop\n \
        KDE        = $(echo $KDE)  : Install Ubuntu KDE Plasma desktop\n \
        NEON       = $(echo $NEON)  : Install Neon KDE Plasma desktop\n \
        NVIDIA     = $(echo $NVIDIA)  : Install Nvidia drivers\n \
        SOF        = $(echo $SOF)  : Install Sound Open Firmware ${SOF_VERSION} binaries\n \
        DISCENC    = $(echo $DISCENC)  : Enable disk encryption (No, LUKS, ZFS)\n \
        DROPBEAR   = $(echo $DROPBEAR)  : Enable Dropbear unlocking of encrypted disks\n \
        Swap size  = $(echo $SIZE_SWAP)M $([ ${SIZE_SWAP} -eq 0 ] && echo ': DISABLED')\n" \
        ${box_height} 79
        RET=${?}
        [[ ${RET} = 1 ]] && exit 1
    fi # Check for WIPE_FRESH
} # show_options()


# -------------------------------------------------------------------------------------------------------
log_options() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Log all the variables used
    # NOTE: tabs as first char to handle indented heredoc
    cat <<- EOF
	==========================================================================
	   DEBUG                   = ${DEBUG}
	   PACKERCI                = ${PACKERCI}
	   MYHOSTNAME              = ${MYHOSTNAME}
	   RESCUE                  = ${RESCUE}
	   DELAY                   = ${DELAY}
	   SUITE                   = ${SUITE}
	   POOLNAME                = ${POOLNAME}
	   SECUREBOOT              = ${SECUREBOOT}
	   AUTOSIGN                = ${AUTOSIGN}
	   USERNAME                = ${USERNAME}
	   UCOMMENT                = "${UCOMMENT}"
	   AUTHKEYS                = ${AUTHKEYS}
	   DISCENC                 = ${DISCENC}
	   DROPBEAR                = ${DROPBEAR}
	   ZREPL                   = ${ZREPL}
	   GOOGLE                  = ${GOOGLE}
	   SOF                     = ${SOF}
	   SOF_VERSION             = ${SOF_VERSION}
	   PROXY                   = ${PROXY}
	   HWE                     = ${HWE}
	   GNOME                   = ${GNOME}
	   XFCE                    = ${XFCE}
	   NEON                    = ${NEON}
	   KDE                     = ${KDE}
	   NVIDIA                  = ${NVIDIA}
	   HIBERNATE               = ${HIBERNATE}
	   SIZE_SWAP               = ${SIZE_SWAP}
	   PARTITION_BOOT          = ${PARTITION_BOOT}
	   PARTITION_SWAP          = ${PARTITION_SWAP}
	   PARTITION_DATA          = ${PARTITION_DATA}
	   PARTITION_WIND          = ${PARTITION_WIND}
	   PARTITION_RCVR          = ${PARTITION_RCVR}
	   ZFSBOOTMENU_BINARY_TYPE = ${ZFSBOOTMENU_BINARY_TYPE}
	   ZFSBOOTMENU_REPO_TYPE   = ${ZFSBOOTMENU_REPO_TYPE}
	   ZFSBOOTMENU_CMDLINE     = ${ZFSBOOTMENU_CMDLINE}
	   WIPE_FRESH              = ${WIPE_FRESH}
	==========================================================================

	EOF
} # log_options()


# -------------------------------------------------------------------------------------------------------
# Install ZFS to local system (livecd)
# Only called when WIPE_FRESH = y
install_zfs() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Pre-OK the zfs-dkms licenses notification
    # NOTE: tabs as first char to handle indented heredoc
    cat > /tmp/selections <<- EOFPRE
		# zfs-dkms license notification
		zfs-dkms        zfs-dkms/note-incompatible-licenses  note
	EOFPRE
    debconf-set-selections < /tmp/selections

    # In case ZFS is already installed in this liveCD, check versions to see
    # if we need to update/upgrade
    # NOTE: Chances are that the kernel module is (eg) 0.8.x and the packages are 0.7.x
    #       so we may as well just upgrade to latest by PPA. Which means building
    #       the newest module, which can take a while.
    # Update ZFS if module mismatch, ZFS encryption selected or update-zfs selected

    # Check if ZFS currently installed in this livecd env
    ZFS_LIVECD=
    if [ -f /usr/sbin/zfs ] || [ -f /sbin/zfs ] ; then
        # Get currently installed version
        ZFS_INSTALLED=$(dpkg -s zfsutils-linux | grep -F Version | cut -d' ' -f2)
        modprobe zfs
        ZFS_MODULE=$(cat /sys/module/zfs/version)
        ZFS_LIVECD=y
    fi
    [ "$ZFS_LIVECD" = "y" ] && echo "ZFS installed with ${ZFS_INSTALLED}, module with ${ZFS_MODULE}"

    apt-get -qq update
    apt-get --no-install-recommends --yes install zfsutils-linux zfs-zed

    # Create an encryption key for LUKs partitions
    if [ "${DISCENC}" = "LUKS" ] ; then
        dd if=/dev/urandom of=/etc/zfs/zroot.lukskey bs=32 count=1
        chmod 0400 /etc/zfs/zroot.lukskey
    fi
    # Put zfs encryption key into place
    # We use two keys so the user can change the home dataset to something else if desired
    if [ "${DISCENC}" = "ZFSENC" ] ; then
        echo "${PASSPHRASE}" > /etc/zfs/zroot.rootkey
        echo "${PASSPHRASE}" > /etc/zfs/zroot.homekey
        chmod 000 /etc/zfs/zroot.rootkey /etc/zfs/zroot.homekey
    fi
} # install_zfs()


# -------------------------------------------------------------------------------------------------------
# For running with NO wipe_fresh, we need to find the current
# poolname, hostname, username
# This assumes we're being run from the system in question
find_zfs_config() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Current root filesystem is on the pool we want
    POOLNAME=$(/usr/bin/df | /usr/bin/grep -E '/$' | /usr/bin/cut -d' ' -f1 | cut -d'/' -f1)
    MYHOSTNAME=$(/usr/bin/hostname)
    # Get userid and full name of main user
    # First see if USERNAME or UCOMMENT are already set in ZFS-root.conf
    if [[ ! -v USERNAME ]] || [[ ! -v UCOMMENT ]] ; then
        [[ ! -v USERNAME ]] && USERNAME=george
        [[ ! -v UCOMMENT ]] && UCOMMENT="George of the Jungle"
        USERINFO=$(whiptail --inputbox "Enter username (login id) and full name of user\nAs in <username> <space> <First and Last name>\n\nlogin full name here\n|---| |------------ - - -  -  -" --title "User information" 11 70 "$USERNAME $UCOMMENT" 3>&1 1>&2 2>&3)
        RET=${?}
        [[ ${RET} = 1 ]] && exit 1
        USERNAME=$(echo "$USERINFO" | cut -d' ' -f1)
        UCOMMENT=$(echo "$USERINFO" | cut -d' ' -f2-)
    fi # Check if USERNAME/UCOMMENT set

    # Get password, confirm and loop until confirmation OK
    if [[ ! -v UPASSWORD ]]; then
        DONE=false
        until ${DONE} ; do
            PW1=$(whiptail --passwordbox "Please enter a password for user $USERNAME" 8 70 --title "User password" 3>&1 1>&2 2>&3)
            PW2=$(whiptail --passwordbox "Please re-enter the password to confirm" 8 70 --title "User password confirmation" 3>&1 1>&2 2>&3)
            [ "$PW1" = "$PW2" ] && DONE=true
        done
        UPASSWORD="$PW1"
    fi # Check if UPASSWORD already set

} # find_zfs_config()


# -------------------------------------------------------------------------------------------------------
# Only called when wiping fresh
partition_disks() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Unmount any mdadm disks that might have been automounted
    # Stop all found mdadm arrays - again, just in case.  Sheesh.
    # shellcheck disable=SC2156  # Not "injecting" filenames - this is standard find -exec
    find /dev -iname md* -type b -exec bash -c "umount {} > /dev/null 2>&1 ; mdadm --stop --force {} > /dev/null 2>&1 ; mdadm --remove {} > /dev/null 2>&1" \;

    ### Partition layout
    for disk in $(seq 0 $(( ${#zfsdisks[@]} - 1))) ; do
        zpool labelclear -f /dev/disk/by-id/${zfsdisks[${disk}]}

        # Wipe mdadm superblock from all partitions found, even if not md raid partition
        mdadm --zero-superblock --force /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_BOOT} > /dev/null 2>&1

        wipefs --all --force /dev/disk/by-id/${zfsdisks[${disk}]}
        sgdisk --zap-all /dev/disk/by-id/${zfsdisks[${disk}]}
        sgdisk --clear /dev/disk/by-id/${zfsdisks[${disk}]}

        # Legacy (BIOS) booting
        sgdisk -a 1                                     /dev/disk/by-id/${zfsdisks[${disk}]}     # Set sector alignment to 1MiB
        sgdisk -n ${PARTITION_BOOT}:1M:+1000M           /dev/disk/by-id/${zfsdisks[${disk}]}     # Create partition 1/BOOT 1M size
        sgdisk -A ${PARTITION_BOOT}:set:2               /dev/disk/by-id/${zfsdisks[${disk}]}     # Turn legacy boot attribute on
        sgdisk -c ${PARTITION_BOOT}:"BOOT_EFI_${disk}"  /dev/disk/by-id/${zfsdisks[${disk}]}     # Set partition name to BOOT_EFI_n
        sgdisk -t ${PARTITION_BOOT}:EF00                /dev/disk/by-id/${zfsdisks[${disk}]}     # Set partition type to EFI

        #
        # TODO: figure out partitions for both ZFS and LUKS encryption
        #       both swap and main partitions
        #
        # For laptop hibernate need swap partition, encrypted or not
        if [ "${HIBERNATE}" = "y" ] ; then
            if [ "${DISCENC}" != "NOENC" ] ; then
                # ZFS or LUKS Encrypted - should be partition type 8309 (Linux LUKS)
                sgdisk -n ${PARTITION_SWAP}:0:+${SIZE_SWAP}M -c ${PARTITION_SWAP}:"SWAP_${disk}" -t ${PARTITION_SWAP}:8309 /dev/disk/by-id/${zfsdisks[${disk}]}
            else
                sgdisk -n ${PARTITION_SWAP}:0:+${SIZE_SWAP}M -c ${PARTITION_SWAP}:"SWAP_${disk}" -t ${PARTITION_SWAP}:8200 /dev/disk/by-id/${zfsdisks[${disk}]}
            fi # DISCENC for ZFS or LUKS
        fi # HIBERNATE

        # Main data partition for root
        if [ "${DISCENC}" = "LUKS" ] ; then
            # LUKS Encrypted - should be partition type 8309 (Linux LUKS)
            # wipefs --all --force /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_DATA}
            # zpool labelclear -f /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_DATA}
            sgdisk -n ${PARTITION_DATA}:0:0 -c ${PARTITION_DATA}:"ZFS_${disk}" -t ${PARTITION_DATA}:8300 /dev/disk/by-id/${zfsdisks[${disk}]}
            apt-get -qq --no-install-recommends --yes install cryptsetup
        else
        # Unencrypted or ZFS encrypted
            sgdisk -n ${PARTITION_DATA}:0:0 -c ${PARTITION_DATA}:"ZFS_${disk}" -t ${PARTITION_DATA}:BF00 /dev/disk/by-id/${zfsdisks[${disk}]}
        fi # DISCENC for LUKS

        #
        # Example partition creation for Windows - be sure to change :0:0 above to :0:+<some size> and +500G here to appropriate
        #
        # sgdisk -n ${PARTITION_WIND}:0:+500G -c ${PARTITION_WIND}:"WIN11_${disk}" -t ${PARTITION_WIND}:C12A /dev/disk/by-id/${zfsdisks[${disk}]}
        # sgdisk -n ${PARTITION_RCVR}:0:0     -c ${PARTITION_RCVR}:"RCVR_${disk}"  -t ${PARTITION_RCVR}:2700 /dev/disk/by-id/${zfsdisks[${disk}]}
    done

    # Refresh partition information
    partprobe

    # Have to wait a bit for the partitions to actually show up
    echo "Wait for partition info to settle out"
    sleep 5

    # Build list of partitions to use for ...
    # Boot partition (mirror across all disks)
    PARTSBOOT=
    PARTSSWAP=
    # ZFS partitions to create zpool with
    ZPOOLDISK=
    for disk in $(seq 0 $(( ${#zfsdisks[@]} - 1))) ; do
        PARTSSWAP="/dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_SWAP} ${PARTSSWAP}"
        PARTSBOOT="/dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_BOOT} ${PARTSBOOT}"
        if [ "${DISCENC}" = "LUKS" ]; then
            ZPOOLDISK="/dev/mapper/root_crypt${disk} ${ZPOOLDISK}"
        else
            ZPOOLDISK="/dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_DATA} ${ZPOOLDISK}"
        fi
    done
} #partition_disks()


# -------------------------------------------------------------------------------------------------------
# Only called when WIPE_FRESH = y
setup_swap_partition() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Create SWAP volume for HIBERNATE, encrypted maybe
    # Just using individual swap partitions - could use mdadm to mirror/raid
    # them up, but meh, why ?
    if [ "${HIBERNATE}" = "y" ] ; then
        # Hibernate, so we need a real swap partition(s)
        for disk in $(seq 0 $(( ${#zfsdisks[@]} - 1))) ; do

            case ${DISCENC} in
                LUKS)
                    echo "Encrypting swap partition ${disk} size ${SIZE_SWAP}M"
                    echo "${PASSPHRASE}" | cryptsetup luksFormat --type luks2 -c aes-xts-plain64 -s 512 -h sha256 /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_SWAP}
                    echo "${PASSPHRASE}" | cryptsetup luksOpen /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_SWAP} swap_crypt${disk}
                    mkswap -f /dev/mapper/swap_crypt${disk}

                    # Add the generated key from /etc/zfs/zroot.lukskey
                    echo "${PASSPHRASE}" | cryptsetup luksAddKey /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_SWAP} /etc/zfs/zroot.lukskey
                    ;;

                ZFSENC)
                    # ZFS encryption can just use a regular partition
                    mkswap -f /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_SWAP}
                    ;;

                NOENC)
                    # Not LUKS, so just use a regular partition
                    mkswap -f /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_SWAP}
                    ;;
            esac
        done
    fi #HIBERNATE
} # setup_swap_partition()


# -------------------------------------------------------------------------------------------------------
# Only called when WIPE_FRESH = y
luks_encrypt_root() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Encrypt root volume maybe
    if [ "${DISCENC}" = "LUKS" ] ; then
        for disk in $(seq 0 $(( ${#zfsdisks[@]} - 1))) ; do
            # Encrypted LUKS root
            echo "Encrypting root ZFS ${disk}"
            echo "${PASSPHRASE}" | cryptsetup luksFormat --type luks2 -c aes-xts-plain64 -s 512 -h sha256 /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_DATA}
            echo "${PASSPHRASE}" | cryptsetup luksOpen /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_DATA} root_crypt${disk}

            # Add the generated key from /etc/zfs/zroot.lukskey
            echo "${PASSPHRASE}" | cryptsetup luksAddKey /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_DATA} /etc/zfs/zroot.lukskey
        done
    fi
} # luks_encrypt_root()


# -------------------------------------------------------------------------------------------------------
# Only called when WIPE_FRESH = y
create_root_pool() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # COMPLETELY clear out build dir
    rm -rf ${ZFSBUILD}
    mkdir -p ${ZFSBUILD}

    # Create root pool
    case ${DISCENC} in
        LUKS)
            echo "Creating root pool ${POOLNAME}"
            # shellcheck disable=SC2086  # quoting here kills the zpool create
            zpool create -f -o ashift=12 -o autotrim=on ${SUITE_ROOT_POOL} \
                 -O acltype=posixacl -O canmount=off -O compression=lz4 \
                 -O atime=off \
                 -O normalization=formD -O relatime=on -O xattr=sa \
                 -O mountpoint=/ -R ${ZFSBUILD} \
                 ${POOLNAME} ${RAIDLEVEL} ${ZPOOLDISK}
            ;;

        # With ZFS encryption we don't encrypt the pool, we encrypt individual
        # datasets hierarchies
        NOENC|ZFSENC)
            # Unencrypted
            # Certain features must be disabled to boot
            #  -o feature@project_quota=disabled \
            #  -o feature@spacemap_v2=disabled \
            echo "Creating root pool ${POOLNAME}"
            # shellcheck disable=SC2086  # quoting here kills the zpool create
            zpool create -f -o ashift=12 -o autotrim=on ${SUITE_ROOT_POOL} \
              -O acltype=posixacl -O canmount=off -O compression=lz4 \
              -O atime=off \
              -O normalization=formD -O relatime=on -O xattr=sa \
              -O mountpoint=none -R ${ZFSBUILD} \
              ${POOLNAME} ${RAIDLEVEL} ${ZPOOLDISK}
            ;;

        *)
            # Unknown option
            echo "Unknown option DISCENC = ${DISCENC}"
            exit 1
            ;;
    esac
} # create_root_pool()


# -------------------------------------------------------------------------------------------------------
# Only called when WIPE_FRESH = y
create_zfs_datasets() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Main filesystem datasets

    echo "Creating main zfs datasets"
    # Container for root filesystems - possibly zfs native encrypted
    if [ "${DISCENC}" = "ZFSENC" ] ; then
        echo "${PASSPHRASE}" | zfs create -o canmount=off -o mountpoint=none ${ZFSENC_ROOT_OPTIONS} ${POOLNAME}/ROOT
    else
        zfs create -o canmount=off -o mountpoint=none ${POOLNAME}/ROOT
    fi

    # Actual dataset for suite we are installing now
    zfs create -o canmount=noauto -o mountpoint=/ ${POOLNAME}/ROOT/${SUITE}

    # Even though we set the bootfs option below, we also set the root dataset commandline
    # to point to the root dataset.  This will allow this root dataset to be booted normally
    # if the bootfs option is ever changed to a different root dataset
    # via the WIPE_FRESH=n to install a different Ubuntu distro
    zfs set org.zfsbootmenu:commandline="rw quiet root=zfs:${POOLNAME}/ROOT/${SUITE}" ${POOLNAME}/ROOT/${SUITE}
    zpool set bootfs=${POOLNAME}/ROOT/${SUITE} ${POOLNAME}
    zfs mount ${POOLNAME}/ROOT/${SUITE}

    if [ "${DISCENC}" != "NOENC" ] ; then
        # Making sure we have the LUKS raw key available and/or
        # Making sure we have the non-root key used for other datasets (/home)
        mkdir -p ${ZFSBUILD}/etc/zfs
        cp /etc/zfs/zroot.*key ${ZFSBUILD}/etc/zfs
    fi

    # zfs create pool/home and main user home dataset - possibly zfs native encrypted
    if [ "${DISCENC}" = "ZFSENC" ] ; then
        echo "${PASSPHRASE}" | zfs create -o canmount=off -o mountpoint=none -o compression=lz4 -o atime=off ${ZFSENC_HOME_OPTIONS} ${POOLNAME}/home
    else
        zfs create -o canmount=off -o mountpoint=none -o compression=lz4 -o atime=off ${POOLNAME}/home
    fi
    zfs create -o canmount=on -o mountpoint=/home/${USERNAME} ${POOLNAME}/home/${USERNAME}
    zfs create -o canmount=on -o mountpoint=/root ${POOLNAME}/home/root

    # If this system will use Docker (which manages its own datasets & snapshots):
    zfs create -o com.sun:auto-snapshot=false -o mountpoint=/var/lib/docker ${POOLNAME}/docker

    # If no HIBERNATE partition (not laptop, no resume etc) then just create
    # a zvol for swap.  Could not create this in the block above for swap because
    # the root pool didn't exist yet.
    # Put it under ${POOLNAME}/ROOT so it gets encrypted if we're using ZFSENC
    if [ "${HIBERNATE}" = "n" ] && [ ${SIZE_SWAP} -ne 0 ] ; then
        # No Hibernate, so just use a zfs volume for swap
        echo "Creating swap zfs dataset size ${SIZE_SWAP}M"
        # zfs create -V ${SIZE_SWAP}M -b $(getconf PAGESIZE) -o compression=zle \
        zfs create -V ${SIZE_SWAP}M -o compression=zle \
          -o logbias=throughput -o sync=always \
          -o primarycache=metadata -o secondarycache=none \
          -o com.sun:auto-snapshot=false ${POOLNAME}/ROOT/swap
    fi #HIBERNATE
} # create_zfs_datasets()


# -------------------------------------------------------------------------------------------------------
install_debootstrap() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Show what we got before installing
    echo "- $(tput setaf 1)About to debootstrap into ${ZFSBUILD}$(tput sgr0) -----------"
    zfs list -t all
    df -h
    echo "- $(tput setaf 1)About to debootstrap into ${ZFSBUILD}$(tput sgr0) -----------"
    read -r -t 15 -p "Press <enter> to continue (auto-continue in 15secs)"

    # Install basic system
    echo "debootstrap to build initial system"
    debootstrap --include=${SUITE_BOOTSTRAP} ${SUITE} ${ZFSBUILD}

    # Ensure device files cannot be created in main POOL
    if [ "${WIPE_FRESH}" == "y" ] ; then
        zfs set devices=off ${POOLNAME}
    fi
} # install_debootstrap()


# -------------------------------------------------------------------------------------------------------
# Only called when WIPE_FRESH = y
setup_boot_partition() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Set up boot partition (UEFI) potentially as mdadm mirror for multi-disk
    if [ ${#zfsdisks[@]} -eq 1 ] ; then
        BOOTDEVRAW=${PARTSBOOT}
    else
        # Unmount any mdadm disks that might have been automounted
        # Stop all found mdadm arrays - again, just in case.  Sheesh.
        # shellcheck disable=SC2156  # Not "injecting" filenames - this is standard find -exec
        find /dev -iname md* -type b -exec bash -c "umount {} > /dev/null 2>&1 ; mdadm --stop --force {} > /dev/null 2>&1 ; mdadm --remove {} > /dev/null 2>&1" \;

        for disk in $(seq 0 $(( ${#zfsdisks[@]} - 1))) ; do
            # Wipe mdadm superblock from all partitions found, even if not md raid partition
            mdadm --zero-superblock --force /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_BOOT} > /dev/null 2>&1
        done
        BOOTDEVRAW="/dev/md/BOOT_EFI"
        # NOTE: Need metadata=1.0 to ensure that mdadm metadata is written to the END of the partition, especially for UEFI
        echo y | mdadm --create ${BOOTDEVRAW} --metadata=1.0 --force --level=mirror --raid-devices=${#zfsdisks[@]} --homehost=${MYHOSTNAME} --name=efi  --assume-clean ${PARTSBOOT}
    fi

    mkfs.vfat -v -F 32 -s 1 -n "BOOT_EFI" ${BOOTDEVRAW} > /dev/null
    echo "UUID=$(blkid -s UUID -o value ${BOOTDEVRAW}) \
          /boot/efi vfat defaults,x-systemd.after=zfs-mount.service 0 0" >> ${ZFSBUILD}/etc/fstab
    mkdir ${ZFSBUILD}/boot/efi
} # setup_boot_partition()


# -------------------------------------------------------------------------------------------------------
setup_network_config() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    echo "${MYHOSTNAME}" > ${ZFSBUILD}/etc/hostname
    echo "127.0.1.1  ${MYHOSTNAME}" >> ${ZFSBUILD}/etc/hosts

    # Set up networking for netplan
    # renderer: networkd is for text mode only, use NetworkManager for gnome
    # We create a bridge here with all found ethernet interfaces as slaves
    # Makes it easier to set up multipass or LXD later
    # NOTE: tabs as first char to handle indented heredoc
    cat > ${ZFSBUILD}/etc/netplan/01_netcfg.yaml <<- EOF
		network:
		  version: 2
		  renderer: networkd
		  ethernets:
		    alleths:
		      optional: true
		      match:
		        name: e*
		      dhcp4: true
		      dhcp6: true
		      wakeonlan: true
		      # === With the bridge config below, set dhcp to false
		      # dhcp4: false
		      # dhcp6: false

		# bridges:
		#   br0:
		#     interfaces: [alleths]
		#     # === Example static IP address
		#     # addresses: [192.168.2.8/24]
		#     # Set default mtu to 9000 jumbo frames
		#     mtu: 9000
		#     dhcp4: yes
		#     dhcp6: yes
		#     wakeonlan: true
		#     # === Only need routes: or gateway4: if NOT using DHCP
		#     # === gateway4 is deprecated, use routes instead
		#     # gateway4: 192.168.2.4
		#     # === For focal/20.04 or jammy/22.04 and above
		#     # routes:
		#     #   - to: default
		#     #     via: 192.168.2.4
		#     #     metric: 100
		#     #     mtu: 1472
		#     #   - to: 192.168.0.0/16
		#     #     scope: link
		#     #     mtu: 9000
		#     nameservers:
		#       addresses: [127.0.0.53, 8.8.8.8, 8.8.4.4]
		#     parameters:
		#       stp: false
		#       forward-delay: 4
	EOF
} # setup_network_config()


# -------------------------------------------------------------------------------------------------------
setup_apt_config() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    if [ "${PROXY}" ]; then
        # This is for apt-get
        echo "Acquire::http::proxy \"${PROXY}\";" > ${ZFSBUILD}/etc/apt/apt.conf.d/03proxy
    fi # PROXY

# sources - NOTE: MUST have actual TABs for each heredoc line because of <<-
    case ${SUITE} in
        bionic)
            # Old sources setup before deb822
            # TABs for this
            cat > ${ZFSBUILD}/etc/apt/sources.list <<- EOF
				deb http://archive.ubuntu.com/ubuntu ${SUITE} main multiverse restricted
				deb-src http://archive.ubuntu.com/ubuntu ${SUITE} main multiverse restricted

				deb http://security.ubuntu.com/ubuntu ${SUITE}-security main multiverse restricted
				deb-src http://security.ubuntu.com/ubuntu ${SUITE}-security main multiverse restricted

				deb http://archive.ubuntu.com/ubuntu ${SUITE}-updates main multiverse restricted
				deb-src http://archive.ubuntu.com/ubuntu ${SUITE}-updates main multiverse restricted

				deb http://archive.ubuntu.com/ubuntu ${SUITE}-backports main multiverse restricted
				deb-src http://archive.ubuntu.com/ubuntu ${SUITE}-backports main multiverse restricted
			EOF

            # We put universe into its own .list file so ansible apt_repository will match
            # TABs for this
            cat > ${ZFSBUILD}/etc/apt/sources.list.d/ubuntu_universe.list <<- EOF
				deb http://archive.ubuntu.com/ubuntu ${SUITE} universe
				deb-src http://archive.ubuntu.com/ubuntu ${SUITE} universe

				deb http://security.ubuntu.com/ubuntu ${SUITE}-security universe
				deb-src http://security.ubuntu.com/ubuntu ${SUITE}-security universe

				deb http://archive.ubuntu.com/ubuntu ${SUITE}-updates universe
				deb-src http://archive.ubuntu.com/ubuntu ${SUITE}-updates universe

				deb http://archive.ubuntu.com/ubuntu ${SUITE}-backports universe
				deb-src http://archive.ubuntu.com/ubuntu ${SUITE}-backports universe
			EOF
            ;;
        *)
            # Everything later than bionic can use the deb822 format
            # TABs for this
            cat > ${ZFSBUILD}/etc/apt/sources.list.d/ubuntu.sources <<- EOF
				Types: deb
				URIs: http://us.archive.ubuntu.com/ubuntu/
				Suites: ${SUITE} ${SUITE}-updates ${SUITE}-backports
				Components: main restricted universe multiverse
				Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

				Types: deb
				URIs: http://security.ubuntu.com/ubuntu/
				Suites: ${SUITE}-security
				Components: main restricted universe multiverse
				Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
			EOF

            # Backup any existing sources.list
            [ -e ${ZFSBUILD}/etc/apt/sources.list ] && mv ${ZFSBUILD}/etc/apt/sources.list ${ZFSBUILD}/etc/apt/sources.list.orig

            # Create new empty sources.list
            # TABs for this
            cat > ${ZFSBUILD}/etc/apt/sources.list <<- EOF
				# Ubuntu sources have moved to the /etc/apt/sources.list.d/ubuntu.sources
				# file, which uses the deb822 format. Use deb822-formatted .sources files
				# to manage package sources in the /etc/apt/sources.list.d/ directory.
				# See the sources.list(5) manual page for details.
			EOF
            ;;
    esac
} # setup_apt_config()


# -------------------------------------------------------------------------------------------------------
setup_googleauth_refind() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    # Google Authenticator config - put to /root to be moved to /home/${USERNAME} in setup.sh
    if [ "${GOOGLE}" = "y" ] ; then
        cp /tmp/google_auth.txt ${ZFSBUILD}/root
    fi
    
    # Copy logo for rEFInd
    [ -e logo_sm.jpg ] && cp logo_sm.jpg ${ZFSBUILD}/root/logo_sm.jpg
    [ -e logo.jpg ] && cp logo.jpg ${ZFSBUILD}/root/logo.jpg
    [ -e logo.png ] && cp logo.png ${ZFSBUILD}/root/logo.png
    [ -e os_linux.png ] && cp os_linux.png ${ZFSBUILD}/root/os_linux.png
} # setup_googleauth_refind()


# -------------------------------------------------------------------------------------------------------
# Begin building the Setup.sh that will run the chroot
prep_setup() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    echo "Creating Setup.sh in new system for chroot"
    cat > ${ZFSBUILD}/root/Setup.sh <<- EOF
		#!/bin/bash

		export DEBUG=${DEBUG}
		export PACKERCI=${PACKERCI}
		export RESCUE=${RESCUE}
		export BOOTDEVRAW=${BOOTDEVRAW}
		export DELAY=${DELAY}
		export SUITE=${SUITE}
		export POOLNAME=${POOLNAME}
		export SECUREBOOT=${SECUREBOOT}
		export AUTOSIGN=${AUTOSIGN}
		export PASSPHRASE=${PASSPHRASE}
		export USERNAME=${USERNAME}
		export UPASSWORD="${UPASSWORD}"
		export UCOMMENT="${UCOMMENT}"
		export DISCENC=${DISCENC}
		export DROPBEAR=${DROPBEAR}
		export AUTHKEYS=${AUTHKEYS}
		export ZREPL=${ZREPL}
		export GOOGLE=${GOOGLE}
		export SOF=${SOF}
		export SOF_VERSION=${SOF_VERSION}
		export PROXY=${PROXY}
		export HWE=${HWE}
		export GNOME=${GNOME}
		export XFCE=${XFCE}
		export NEON=${NEON}
		export KDE=${KDE}
		export NVIDIA=${NVIDIA}
		export HIBERNATE=${HIBERNATE}
		export SIZE_SWAP=${SIZE_SWAP}
		export PARTITION_BOOT=${PARTITION_BOOT}
		export PARTITION_SWAP=${PARTITION_SWAP}
		export PARTITION_DATA=${PARTITION_DATA}
		export ZFSBOOTMENU_BINARY_TYPE=${ZFSBOOTMENU_BINARY_TYPE}
		export ZFSBOOTMENU_REPO_TYPE=${ZFSBOOTMENU_REPO_TYPE}
		export ZFSBOOTMENU_CMDLINE=${ZFSBOOTMENU_CMDLINE}
		export USE_ZSWAP="${USE_ZSWAP}"
		export WIPE_FRESH="${WIPE_FRESH}"

		[[ -v DEBUG ]] && set -x
		[[ -v PACKERCI ]] && set -x

	EOF

    # Only need the list of disks for a fresh install
    if [ "${WIPE_FRESH}" == "y" ] ; then
        for disk in $(seq 0 $(( ${#zfsdisks[@]} - 1))) ; do
            echo "zfsdisks[${disk}]=${zfsdisks[${disk}]}" >> ${ZFSBUILD}/root/Setup.sh
        done
    fi

    # Add SSHPUBKEY and Host keys from ZFS-root.conf if defined
    [[ -v SSHPUBKEY ]] && echo "export SSHPUBKEY=\"${SSHPUBKEY}\"" >> ${ZFSBUILD}/root/Setup.sh
    # Ugly hack to get multiline variable into Setup.sh
    # Note using single quotes like this  HOST_RSA_KEY='blahblah' surrounded by double quotes
    [[ -v HOST_ECDSA_KEY_PUB ]] && echo "export HOST_ECDSA_KEY_PUB=\"${HOST_ECDSA_KEY_PUB}\"" >> ${ZFSBUILD}/root/Setup.sh
    if [[ -v HOST_ECDSA_KEY ]] ; then
        echo -n "export HOST_ECDSA_KEY='" >> ${ZFSBUILD}/root/Setup.sh
        echo "${HOST_ECDSA_KEY}'" >> ${ZFSBUILD}/root/Setup.sh
    fi
    [[ -v HOST_RSA_KEY_PUB ]] && echo "export HOST_RSA_KEY_PUB=\"${HOST_RSA_KEY_PUB}\"" >> ${ZFSBUILD}/root/Setup.sh
    if [[ -v HOST_RSA_KEY ]] ; then
        echo -n "export HOST_RSA_KEY='" >> ${ZFSBUILD}/root/Setup.sh
        echo "${HOST_RSA_KEY}'" >> ${ZFSBUILD}/root/Setup.sh
    fi
    [[ -v HOST_ED25519_KEY_PUB ]] && echo "export HOST_ED25519_KEY_PUB=\"${HOST_ED25519_KEY_PUB}\"" >> ${ZFSBUILD}/root/Setup.sh
    if [[ -v HOST_ED25519_KEY ]] ; then
        echo -n "export HOST_ED25519_KEY='" >> ${ZFSBUILD}/root/Setup.sh
        echo "${HOST_ED25519_KEY}'" >> ${ZFSBUILD}/root/Setup.sh
    fi
} # prep_setup()


# -------------------------------------------------------------------------------------------------------
# The rest of the Setup.sh to run in the chroot
build_setup() {
    echo "--------------------------------------------------------------------------------"
    echo "${FUNCNAME[0]}"
    mkdir -p ${ZFSBUILD}/root
cat >> ${ZFSBUILD}/root/Setup.sh << '__EOF__'
    # Setup inside chroot

    # efi-shell-x64 (shellx64.efi) only from noble/24.04 on
    case ${SUITE} in
        questing)
            SUITE_NUM="25.10"
            SUITE_BSDUTILS="bsdextrautils"
            EFI_SHELL="efi-shell-x64"
            ;;
        plucky)
            SUITE_NUM="25.04"
            SUITE_BSDUTILS="bsdextrautils"
            EFI_SHELL="efi-shell-x64"
            ;;
        noble)
            SUITE_NUM="24.04"
            SUITE_BSDUTILS="bsdmainutils"
            EFI_SHELL="efi-shell-x64"
            ;;
        jammy)
            SUITE_NUM="22.04"
            SUITE_BSDUTILS="bsdmainutils"
            ;;
        focal)
            SUITE_NUM="20.04"
            SUITE_BSDUTILS="bsdmainutils"
            ;;
        *)
            SUITE_NUM="24.04"
            SUITE_BSDUTILS="bsdmainutils"
            ;;
    esac

    # Make sure we're using a tmpfs for /tmp
    # Up to noble/24.04 use /usr/share/systemd while plucky/25.04 and above is /usr/lib/systemd
    [ -e /usr/share/systemd/tmp.mount ] && systemctl enable /usr/share/systemd/tmp.mount
    [ -e /usr/lib/systemd/system/tmp.mount ] && systemctl enable /usr/lib/systemd/system/tmp.mount

    ln -s /proc/self/mounts /etc/mtab
    apt-get -qq update
    apt-get -qq --yes --no-install-recommends install software-properties-common debconf-utils mdadm

    # Preseed a few things
    # NOTE: tabs as first char to handle indented heredoc
    cat > /tmp/selections <<- EOFPRE
		# zfs-dkms license notification
		zfs-dkms        zfs-dkms/note-incompatible-licenses  note
		# tzdata
		tzdata  tzdata/Zones/US                         select Eastern
		tzdata  tzdata/Zones/America                    select New_York
		tzdata  tzdata/Areas                            select US
		console-setup   console-setup/codeset47         select  # Latin1 and Latin5 - western Europe and Turkic languages
	EOFPRE
    cat /tmp/selections | debconf-set-selections

    # Set up locale - must set langlocale variable (defaults to en_US)
    # NOTE: tabs as first char to handle indented heredoc
    cat > /etc/default/locale <<- EOFLOCALE
	 	# LC_ALL=en_US.UTF-8
	 	LANG=en_US.UTF-8
	 	LANGUAGE=en_US:en
	EOFLOCALE
    cat > /etc/locale.gen <<- EOFLOCALEGEN
		en_US.UTF-8 UTF-8
	EOFLOCALEGEN
    cat /etc/default/locale >> /etc/environment
    locale-gen --purge "en_US.UTF-8"
    dpkg-reconfigure -f noninteractive locales

    echo "America/Boise" > /etc/timezone
    ln -fs /usr/share/zoneinfo/US/Mountain /etc/localtime
    dpkg-reconfigure -f noninteractive tzdata

    # NOTE: Very important
    #       Do NOT install initramfs-tools next to dracut
    #       They wrestle and knock each other out
    #       Same with grub - fighting rEFInd
    apt-mark hold cryptsetup-initramfs zfs-initramfs initramfs-tools initramfs-tools-bin initramfs-tools-core grub-efi-amd64 grub-efi-amd64-signed grub-efi-amd64-bin grub-common grub2-common lilo

    # Make sure the kernel is installed and configured before ZFS
    apt-get -qq --yes --no-install-recommends install linux-generic${HWE} linux-headers-generic${HWE} linux-image-generic${HWE}

    #
    # The "old" kernel links mess up zfsbootmenu generation, so remove them
    # Don't need them for an initial install anyway
    #
    rm /boot/vmlinuz.old /boot/initrd.img.old

    apt-get -qq --no-install-recommends --yes install zfs-zed zfsutils-linux

    # jammy/22.04 moved zfs from /sbin/zfs to /usr/sbin/zfs
    ZFSLOCATION=$(which zfs)

    if [ "${DISCENC}" != "NOENC" ] ; then
        apt-get -qq --yes --no-install-recommends install cryptsetup keyutils
    fi

    # Ensure cachefile exists and zfs-import-cache is active
    # https://github.com/zfsonlinux/zfs/issues/8885
    zpool set cachefile=/etc/zfs/zpool.cache ${POOLNAME}
    systemctl enable zfs.target zfs-import-cache zfs-mount zfs-import.target


    # Configure Dracut to load ZFS support
    # Need gcc to get libgcc_s.so for dracut_install to work
    apt-get -qq --yes install dracut-core zfs-dracut ${SUITE_BSDUTILS} gcc

    # NOTE: tabs as first char to handle indented heredoc
    cat <<- END > /etc/dracut.conf.d/100-zol.conf
		nofsck="yes"
		add_dracutmodules+=" zfs "
		omit_dracutmodules+=" btrfs "
	END

    # Fix zfs dracut - https://github.com/openzfs/zfs/issues/13398
    # Need gcc to get libgcc_s.so for dracut_install to work
    sed -i '/\*\*/s/\*\*/*\/*/' /usr/lib/dracut/modules.d/90zfs/module-setup.sh

    # Fix zfs bootfs systemd services
    # https://github.com/openzfs/zfs/pull/13585/files
    # https://github.com/openzfs/zfs/issues/14475
    # /usr/lib/dracut/modules.d/90zfs/zfs-rollback-bootfs.service
    # /usr/lib/dracut/modules.d/90zfs/zfs-snapshot-bootfs.service
    sed -i 's/-ExecStart=/ExecStart=-/ ; s/BOOTFS" SNAPNAME/BOOTFS"; SNAPNAME/' /usr/lib/dracut/modules.d/90zfs/zfs-snapshot-bootfs.service
    sed -i 's/-ExecStart=/ExecStart=-/ ; s/BOOTFS" SNAPNAME/BOOTFS"; SNAPNAME/' /usr/lib/dracut/modules.d/90zfs/zfs-rollback-bootfs.service


    #
    # Install rEFInd and syslinux
    #

    # First check for efivars and mount if necessary
    # LiveCD on Lenovo laptops for some reason don't always mount it ...
    # efibootmgr results in 'EFI variables are not supported on this system'
    EFIVARS_CNT=$(ls -1 /sys/firmware/efi/efivars | wc -l)
    if [ ${EFIVARS_CNT} -eq 0 ] ; then
      echo "Need to mount EFIVARS"
      mount -t efivarfs efivarfs /sys/firmware/efi/efivars
    fi

    mount /boot/efi

    # We don't want dpkg/apt to install rEFInd to ESP because we do it right below
    # with refind-install
    # If non WIPE_FRESH we just want rEFInd installed, but not installed to ESP
    # since it's already there
    cat > /tmp/selectionsref <<- EOFREF
		# Don't install rEFInd to ESP - handle manually later
		refind  refind/install_to_esp   boolean false
	EOFREF
    debconf-set-selections < /tmp/selectionsref
    # efi-shell-x64 (shellx64.efi) only from noble/24.04 on
    # EFI_SHELL set above to either efi-shell-x64 or left blank
    DEBIAN_FRONTEND=noninteractive apt-get -qq --yes install refind efibootmgr ${EFI_SHELL}

    apt-get -qq --yes install syslinux syslinux-common extlinux dosfstools unzip

    # For a non-wipe_fresh, we don't actually need to install refind since it's already
    # there in /boot/efi - so only do this if we're wiping fresh
    if [ "${WIPE_FRESH}" == "y" ] ; then     # <<<<<------------------------------------------------ WIPE_FRESH ------ VVVVV
        refind-install --yes

        # For multiple disks, add a startup.nsh and do manual efibootmgr setup
        # since refind-install doesn't handle raid'd ESP partitions
        if [ ${#zfsdisks[@]} -ge 1 ] ; then

            # Set refind on each disk to be a valid bootable efi image
            for DISK in $(seq 0 $(( ${#zfsdisks[@]} - 1))) ; do
                efibootmgr --create --disk /dev/disk/by-id/${zfsdisks[${DISK}]} --part ${PARTITION_BOOT} --loader /EFI/refind/refind_x64.efi --label "rEFInd on disk ${DISK}" --unicode
            done

            ## Replacement startup.nsh to iterate over all disks looking for refind
            # NOTE: tabs as first char to handle indented heredoc
            cat <<- 'EOF' > /boot/efi/startup.nsh
				@echo -off
				cls

				# List all mapped file systems (disks/partitions)
				echo -n "Enumerating filesystems... "
				fs0:
				if %lasterror% == 0 then
				    echo "OK"
				else
				    echo "No filesystems found."
				    goto error
				endif

				set found 0

				for %i in (fs*) do (
				    echo -n "Checking %i for /EFI/refind/refind_x64.efi ... "
				    if exist %i:\EFI\refind\refind_x64.efi then
				        echo "FOUND"
				        echo "Launching rEFInd from %i:"
				        %i:\EFI\refind\refind_x64.efi
				        goto done
				    else
				        echo "not present"
				    endif
				)

				:error
				echo "ERROR: Could not find /EFI/refind/refind_x64.efi on any filesystem."
				goto end

				:done
				echo "rEFInd launched successfully."
				goto end

				:end
			EOF
        fi # multiple boot disks

        mkdir -p /boot/efi/EFI/zfsbootmenu
        # NOTE: tabs as first char to handle indented heredoc
        cat <<- END > /boot/efi/EFI/zfsbootmenu/refind_linux.conf
			# NOTE: The xhci Tearing down USB controller tends to disable USB controllers
			#       on Supermicro X10DHR motherboards, so we disable that hook here.
			#       See https://docs.zfsbootmenu.org/en/v3.0.x/man/zfsbootmenu.7.html
			# NOTE: This will also need to be set in the syslinux-update.sh below
			"Boot to ZFSbootMenu" "zbm.prefer=${POOLNAME} ro quiet loglevel=0 ${ZFSBOOTMENU_CMDLINE}"
		END

        # Copy UEFI shell to EFI system
        if [ -e /usr/share/efi-shell-x64/shellx64.efi ] ; then
            mkdir -p /boot/efi/EFI/tools
            cp /usr/share/efi-shell-x64/shellx64.efi /boot/efi/EFI/tools
        fi

        # If we're running under legacy bios then rEFInd will be installed
        # to /boot/efi/EFI/BOOT - we want it in /boot/efi/EFI/refind
        [ -e /boot/efi/EFI/BOOT ] && mvrefind /boot/efi/EFI/BOOT /boot/efi/EFI/refind
        # Change timout for rEFInd from 20secs to 10secs
        sed -i 's,^timeout .*,timeout 10,' /boot/efi/EFI/refind/refind.conf
        # Add a banner/logo for rEFInd if present
        if [ -e /root/logo.png ] || [ -e /root/logo.jpg ] ; then
            sed -i 's,^#banner_scale,banner_scale,' /boot/efi/EFI/refind/refind.conf
            [ -e /root/logo.jpg ] && sed -i 's,^#banner hostname.bmp,banner logo.jpg,' /boot/efi/EFI/refind/refind.conf
            [ -e /root/logo.png ] && sed -i 's,^#banner hostname.bmp,banner logo.png,' /boot/efi/EFI/refind/refind.conf
            cp /root/logo.{png,jpg} /boot/efi/EFI/refind/
            cp /root/os_linux.png /boot/efi/EFI/refind/icons
        fi

        # Set up syslinux
        mkdir /boot/efi/syslinux
        cp -r /usr/lib/syslinux/modules/bios/* /boot/efi/syslinux
        # Install extlinux
        extlinux --install /boot/efi/syslinux
        # Install the syslinux GPTMBR data
        for DISK in $(seq 0 $(( ${#zfsdisks[@]} - 1))) ; do
            dd bs=440 count=1 conv=notrunc if=/usr/lib/syslinux/mbr/gptmbr.bin of=/dev/disk/by-id/${zfsdisks[${DISK}]}
        done

        # Copy logo for syslinux if there
        [ -e /root/logo_sm.jpg ] && cp /root/logo_sm.jpg /boot/efi/syslinux
    fi # WIPE_FRESH                         # <<<<<------------------------------------------------ WIPE_FRESH ------ ^^^^^


    #
    # Install and configure ZFSBootMenu
    #
    DEBIAN_FRONTEND=noninteractive apt-get --yes install kexec-tools
    apt-get -qq --yes install libconfig-inifiles-perl libsort-versions-perl libboolean-perl fzf mbuffer make curl bsdextrautils git

    # Assign command-line arguments to be used when booting the final kernel
    # For hibernation and resume to work we have to specify which device to resume from
    # Can only resume from ONE device though, so we default to the 1st disk swap partition
    # ZFS native encryption and non-encrypted can use SWAP partition directly
    # LUKS encryption uses the 1st swap_crypt0 device
    if [ "${HIBERNATE}" = "y" ] ; then
        # NOTE: be sure to use real TABS for this heredoc
        cat <<- END > /etc/dracut.conf.d/resume-from-hibernate.conf
			add_dracutmodules+=" resume "
		END

        # Although we have systemd-hibernate, also install pm-utils for pm-hibernate
        apt-get -qq --yes install pm-utils

        if [ "${DISCENC}" = "LUKS" ] ; then
            zfs set org.zfsbootmenu:commandline="rw quiet ${USE_ZSWAP} resume=/dev/mapper/swap_crypt0" ${POOLNAME}/ROOT
            zfs set org.zfsbootmenu:commandline="rw quiet ${USE_ZSWAP} resume=/dev/mapper/swap_crypt0" ${POOLNAME}/ROOT/${SUITE}

            # NOTE: be sure to use real TABS for this heredoc
            cat <<- END > /etc/dracut.conf.d/resume-swap-crypt.conf
				# Needed for resuming from encrypted swap
				add_device+=" /dev/mapper/swap_crypt0 "
				add_dracutmodules+=" crypt "
			END
        else
            zfs set org.zfsbootmenu:commandline="rw quiet ${USE_ZSWAP} resume=UUID=$(blkid -s UUID -o value /dev/disk/by-id/${zfsdisks[0]}-part${PARTITION_SWAP})" ${POOLNAME}/ROOT
            zfs set org.zfsbootmenu:commandline="rw quiet ${USE_ZSWAP} resume=UUID=$(blkid -s UUID -o value /dev/disk/by-id/${zfsdisks[0]}-part${PARTITION_SWAP})" ${POOLNAME}/ROOT/${SUITE}
        fi

        # Needed for any hibernation resume to work, encrypted or not
        # NOTE: be sure to use real TABS for this heredoc
        cat <<- END > /etc/dracut.conf.d/resume-swap-systemd.conf
			# Ensure systemd-hibernate-resume is available
			# add_device+=" UUID=$(blkid -s UUID -o value /dev/disk/by-id/${zfsdisks[0]}-part${PARTITION_SWAP}) "
			add_dracutmodules+=" systemd "
			install_items+=" /usr/lib/systemd/system/systemd-hibernate-resume.service "
		END
    else
        zfs set org.zfsbootmenu:commandline="rw quiet" ${POOLNAME}/ROOT
        zfs set org.zfsbootmenu:commandline="rw quiet" ${POOLNAME}/ROOT/${SUITE}
    fi # Hibernate
    zfs set canmount=noauto ${POOLNAME}/ROOT
    zfs set canmount=noauto ${POOLNAME}/ROOT/${SUITE}

    if [ "${WIPE_FRESH}" == "y" ] ; then     # <<<<<------------------------------------------------ WIPE_FRESH ------ VVVVV
        #
        # Install the ZFSBootMenu package directly
        #

        # If this is NOT a UEFI system then we'll be using syslinux to boot.
        # And that won't work with an EFI image, it needs the vmlinuz/initrd set
        # So if it was trying for an EFI image we force it to the KERNEL version
        # If it was trying for LOCAL then that's fine and leave it be.
        if [ "${ZFSBOOTMENU_BINARY_TYPE}" = "EFI" ] ; then
            [[ ! -d /sys/firmware/efi ]] && ZFSBOOTMENU_BINARY_TYPE=KERNEL
        fi

        echo "ZFSBOOTMENU_BINARY_TYPE = $ZFSBOOTMENU_BINARY_TYPE  ZFSBOOTMENU_REPO_TYPE = $ZFSBOOTMENU_REPO_TYPE ZFSBOOTMENU_CMDLINE = $ZFSBOOTMENU_CMDLINE"

        ## Either the actual zfsbootmenu EFI image
        ## NOTE: syslinux requires the KERNEL version since it needs to use the
        ##       vmlinuz/initrd files to boot with
        if [ "${ZFSBOOTMENU_BINARY_TYPE}" = "EFI" ] ; then
            echo "--- Using zfsbootmenu EFI image"
            curl -L https://get.zfsbootmenu.org/efi/recovery -o /boot/efi/EFI/zfsbootmenu/zfsbootmenu.efi

            # Add rEFInd entry for ZFSBootMenu
            # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
            cat >> /boot/efi/EFI/refind/refind.conf <<- EOF

				# ZFSBootMenu EFI Loader Configuration
				menuentry "ZFSBootMenu" {
				  loader EFI/zfsbootmenu/zfsbootmenu.efi
				  icon EFI/refind/icons/os_ubuntu.png
				}
			EOF
        fi # ZFSBOOTMENU_BINARY_TYPE

        ##  or the unpacked EFI image (vmlinux/initrd)
        ## NOTE: Right now hard-coded version in place.  Need a clean way to get latest version
        ##       Fetch github releases json and parse, like in ansible-git_tools
        if [ "${ZFSBOOTMENU_BINARY_TYPE}" = "KERNEL" ] ; then
            echo "--- Using zfsbootmenu KERNEL files"
            curl -L https://github.com/zbm-dev/zfsbootmenu/releases/download/v3.0.1/zfsbootmenu-recovery-x86_64-v3.0.1-linux6.12.tar.gz -o /usr/local/share/zfsbootmenu.tar.gz
            tar xvzf /usr/local/share/zfsbootmenu.tar.gz --strip-components=1 -C /boot/efi/EFI/zfsbootmenu
            rm -f /usr/local/share/zfsbootmenu.tar.gz
        fi

        # For a binary release setup we still need the syslinux-update.sh script from the repo
        # NOTE: This is in /usr/local/bin so it can be run ad-hoc to update the syslinux config
        #       For a LOCAL install it is in /etc/zfsbootmenu/generate-zbm.post.d/syslinux-update.sh
        #       and run via generate-zbm.sh
        if [ "${ZFSBOOTMENU_BINARY_TYPE}" != "LOCAL" ] ; then
            curl -L https://raw.githubusercontent.com/zbm-dev/zfsbootmenu/master/contrib/syslinux-update.sh -o /boot/efi/syslinux-update.sh
            chmod +x /boot/efi/syslinux-update.sh
            sed -i '
              s/^SYSLINUX_ROOT.*/SYSLINUX_ROOT="\/boot\/efi"/
              s/^KERNEL_PATH.*/KERNEL_PATH="EFI\/zfsbootmenu"/
              s/^SYSLINUX_CONFD.*/SYSLINUX_CONFD="\/boot\/efi\/snippets"/
              s/^ZBM_KCL_ARGS.*/ZBM_KCL_ARGS="zbm.prefer=${POOLNAME} ro quiet loglevel=0 ${ZFSBOOTMENU_CMDLINE}"/
              s/^cp .*/cp "\${SYSLINUX_CFG}" "\${SYSLINUX_ROOT}\/syslinux\/syslinux.cfg"/
             ' /boot/efi/syslinux-update.sh
        fi
    fi # WIPE_FRESH                         # <<<<<------------------------------------------------ WIPE_FRESH ------ ^^^^^

    # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    #   Configuration needed regardless of WIPE_FRESH
    # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

    #### OR install the git repo and build locally

    ### Two choices - tagged release or latest git
    rm -rf /usr/local/share/zfsbootmenu && mkdir -p /usr/local/share/zfsbootmenu

    # Get latest tagged release, sure to work. Base git repo may be in flux
    if [ "${ZFSBOOTMENU_REPO_TYPE}" = "TAGGED" ] ; then
        echo "--- Using zfsbootmenu TAGGED repo"
        curl -L https://get.zfsbootmenu.org/source | tar xz --strip=1 --directory /usr/local/share/zfsbootmenu
    fi

    #### OR For latest just clone

    if [ "${ZFSBOOTMENU_REPO_TYPE}" = "GIT" ] ; then
        echo "--- Using zfsbootmenu GIT repo"
        git clone https://github.com/zbm-dev/zfsbootmenu.git /usr/local/share/zfsbootmenu
    fi

    ## Now install - ONLY if using git repo
    if [ "${ZFSBOOTMENU_BINARY_TYPE}" = "LOCAL" ] ; then
        echo "--- zfsbootmenu building LOCAL"
        cd /usr/local/share/zfsbootmenu
        make install

        # This seems to fail sometimes - gets killed during install
        # PERL_MM_USE_DEFAULT=1 cpan 'YAML::PP'
        # So try the ubuntu package - also need dhcpclient
        apt-get -qq --yes --no-install-recommends install libyaml-pp-perl isc-dhcp-client perl-doc

        #
        # Configure ZFSBootMenu
        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat <<- END > /etc/zfsbootmenu/config.yaml
			Global:
			  ManageImages: true
			  BootMountPoint: /boot/efi
			  DracutConfDir: /etc/zfsbootmenu/dracut.conf.d
			  PreHooksDir: /etc/zfsbootmenu/generate-zbm.pre.d
			  PostHooksDir: /etc/zfsbootmenu/generate-zbm.post.d
			  InitCPIO: false
			  InitCPIOConfig: /etc/zfsbootmenu/mkinitcpio.conf
			Components:
			  ImageDir: /boot/efi/EFI/zfsbootmenu
			  # Versions: false means generate-zbm creates vmlinuz-bootmenu and initramgs-bootmenu.img
			  Versions: false
			  Enabled: true
			EFI:
			  ImageDir: /boot/efi/EFI/zfsbootmenu
			  Versions: 2
			  Enabled: false
			Kernel:
			  CommandLine: zbm.prefer=${POOLNAME} ro quiet loglevel=0 ${ZFSBOOTMENU_CMDLINE}
		END

        # Create pre and post hooks dirs and syslinux snippets dir
        mkdir -p /etc/zfsbootmenu/generate-zbm.pre.d
        mkdir -p /etc/zfsbootmenu/generate-zbm.post.d

        # Copy syslinux-update.sh script and modify to suit
        # This makes generate-zbm create a valid syslinux.cfg that can
        # also include memtest86 snippet
        cp /usr/local/share/zfsbootmenu/contrib/syslinux-update.sh /etc/zfsbootmenu/generate-zbm.post.d
        chmod +x /etc/zfsbootmenu/generate-zbm.post.d/syslinux-update.sh
        sed -i '
          s/^SYSLINUX_ROOT.*/SYSLINUX_ROOT="\/boot\/efi"/
          s/^KERNEL_PATH.*/KERNEL_PATH="EFI\/zfsbootmenu"/
          s/^SYSLINUX_CONFD.*/SYSLINUX_CONFD="\/boot\/efi\/snippets"/
          s/^ZBM_KCL_ARGS.*/ZBM_KCL_ARGS="zbm.prefer=${POOLNAME} ro quiet loglevel=0 ${ZFSBOOTMENU_CMDLINE}"/
          s/^cp .*/cp "\${SYSLINUX_CFG}" "\${SYSLINUX_ROOT}\/syslinux\/syslinux.cfg"/
         ' /etc/zfsbootmenu/generate-zbm.post.d/syslinux-update.sh
    fi # LOCAL

    # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    #   Modifications to /boot/efi only when WIPE_FRESH
    # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    if [ "${WIPE_FRESH}" == "y" ] ; then     # <<<<<------------------------------------------------ WIPE_FRESH ------ VVVVV
        mkdir -p /boot/efi/snippets

        # Header for syslinux.cfg
        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /boot/efi/snippets/01_header <<- EOF
			UI vesamenu.c32
			PROMPT 0

			MENU BACKGROUND logo_sm.jpg
			MENU TITLE Boot Menu
			TIMEOUT 50

		EOF

        # Syslinux hardware info
        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /boot/efi/snippets/06_hardware <<- EOF
			LABEL hdt
			MENU LABEL Hardware Info
			COM32 hdt.c32

		EOF

        # Download and install memtest86
        # EFI version is latest v11, syslinux version is v4
        rm -rf /tmp/memtest86 && mkdir -p /tmp/memtest86/mnt
        mkdir -p /boot/efi/EFI/tools/memtest86
        curl -L https://www.memtest86.com/downloads/memtest86-usb.zip -o /tmp/memtest86/memtest86-usb.zip
        curl -L https://www.memtest86.com/downloads/memtest86-4.3.7-iso.zip -o /tmp/memtest86/memtest86-iso.zip
        # For EFI
           unzip -d /tmp/memtest86 /tmp/memtest86/memtest86-usb.zip memtest86-usb.img
           losetup -P /dev/loop33 /tmp/memtest86/memtest86-usb.img
           mount -o loop /dev/loop33p1 /tmp/memtest86/mnt
           cp /tmp/memtest86/mnt/EFI/BOOT/BOOTX64.efi /boot/efi/EFI/tools/memtest86/memtest86.efi
           umount /tmp/memtest86/mnt
           losetup -d /dev/loop33
        # For Syslinux
           unzip -d /tmp/memtest86 /tmp/memtest86/memtest86-iso.zip Memtest86-4.3.7.iso
           mount -o loop /tmp/memtest86/Memtest86-4.3.7.iso /tmp/memtest86/mnt
           cp /tmp/memtest86/mnt/isolinux/memtest /boot/efi/EFI/tools/memtest86/memtest86.syslinux
           umount /tmp/memtest86/mnt

        # Syslinux entry for memtest86+
        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /boot/efi/snippets/05_memtest86 <<- EOF
			LABEL Memtest86+
			KERNEL /EFI/tools/memtest86/memtest86.syslinux

		EOF


        #
        # Set up LUKS unlocking
        #
        if [ "${DISCENC}" == "LUKS" ] ; then
            for DISK in $(seq 0 $(( ${#zfsdisks[@]} - 1))) ; do
                echo "root_crypt${DISK} UUID=$(blkid -s UUID -o value /dev/disk/by-id/${zfsdisks[${DISK}]}-part${PARTITION_DATA}) /etc/zfs/zroot.lukskey discard,luks,keyfile-timeout=10s" >> /etc/crypttab
                if [ "${HIBERNATE}" == "y" ] ; then
                    echo "swap_crypt${DISK} UUID=$(blkid -s UUID -o value /dev/disk/by-id/${zfsdisks[${DISK}]}-part${PARTITION_SWAP}) /etc/zfs/zroot.lukskey discard,luks,keyfile-timeout=10s" >> /etc/crypttab
                fi
            done

            #
            # Early-stage script for zfsbootmenu - scan for ZFS_ partitions which
            # should be LUKS encrypted and try to open them all
            #
            # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
            cat > /usr/local/bin/zfsbootmenu_luks_unlock.sh <<- 'EOF'
				#!/bin/bash

				sources=(
				  /lib/profiling-lib.sh
				  /etc/zfsbootmenu.conf
				  /lib/zfsbootmenu-core.sh
				  /lib/kmsg-log-lib.sh
				  /etc/profile
				)

				for src in "${sources[@]}"; do
				  # shellcheck disable=SC1090
				  if ! source "${src}" > /dev/null 2>&1 ; then
				    echo -e "\033[0;31mWARNING: ${src} was not sourced; unable to proceed\033[0m"
				    exit 1
				  fi
				done
				unset src sources

				# Ensure glob expands to nothing for non-matches
				shopt -s nullglob
				ZFS_PARTS=(/dev/disk/by-partlabel/{SWAP_*,ZFS_*})

				echo "Found these partitions for LUKS encryption"
				for idx in ${!ZFS_PARTS[@]} ; do echo "${ZFS_PARTS[$idx]}" ; done
				echo ""

				# Read passphrase for LUKS encryption into $REPLY
				read -s -p "LUKS encryption passphrase : "

				tput clear
				colorize red "${header}\n\n"
				for idx in ${!ZFS_PARTS[@]} ; do
				    # Grab just ZFS_0 or SWAP_0
				    test_luks=${ZFS_PARTS[$idx]#/dev/disk/by-partlabel/}
				    # luks is the full path to the disk partition
				    luks=${ZFS_PARTS[$idx]}
				    # Set $dm to root_crypt0 or swap_crypt0 depending on basename
				    [ "${test_luks%_*}" == "ZFS" ] && dm=root_crypt${idx}
				    [ "${test_luks%_*}" == "SWAP" ] && dm=swap_crypt${idx}

				    if ! cryptsetup isLuks ${luks} >/dev/null 2>&1 ; then
				        zwarn "LUKS device ${luks} missing LUKS partition header"
				        exit
				    fi

				    if cryptsetup status "${dm}" >/dev/null 2>&1 ; then
				        zinfo "${dm} already active, continuing"
				        continue
				    fi

				    header="$( center_string "[CTRL-C] cancel luksOpen attempts" )"

				    # https://fossies.org/linux/cryptsetup/docs/Keyring.txt
				    echo $REPLY | cryptsetup luksOpen ${luks} ${dm}
				    ret=$?

				    # successfully entered a passphrase
				    if [ "${ret}" -eq 0 ] ; then
                        echo "${luks} opened as ${dm}"
				        zdebug "$(
				            cryptsetup status "${dm}"
				        )"
				        continue
				    fi

				    # ctrl-c'd the process
				    if [ "${ret}" -eq 1 ] ; then
				        zdebug "canceled luksOpen attempts via SIGINT"
				        exit
				    fi

				    # failed all password attempts
				    if [ "${ret}" -eq 2 ] ; then
				        if timed_prompt -e "emergency shell" \
				            -r "continue unlock attempts" \
				            -p "Continuing in %0.2d seconds" ; then
				            continue
				        else
				            emergency_shell "unable to unlock LUKS partition"
				        fi
				    fi
				done
                sleep 5  # Allow user to see unlocked partitions
			EOF
            chmod +x /usr/local/bin/zfsbootmenu_luks_unlock.sh

            echo 'zfsbootmenu_early_setup+=" /usr/local/bin/zfsbootmenu_luks_unlock.sh "' > /etc/zfsbootmenu/dracut.conf.d/luks_zbm.conf
        fi #DISCENC


        # Using a swap partition ?
        if [ "${HIBERNATE}" == "y" ] ; then

            # Hibernate is enabled - we HAVE to use a swap partition
            # Also, only works with a single disk (as in laptop)
            if [ "${DISCENC}" = "LUKS" ] ; then

                # LUKS encrypted
                for disk in $(seq 0 $(( ${#zfsdisks[@]} - 1))) ; do
                    echo "/dev/mapper/swap_crypt${disk} none swap discard,sw 0 0" >> /etc/fstab
                done

            else

                # Not LUKS encrypted
                for disk in $(seq 0 $(( ${#zfsdisks[@]} - 1))) ; do
                    echo "UUID=$(blkid -s UUID -o value /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_SWAP}) none swap discard,sw 0 0" >> /etc/fstab
                done

            fi # DISCENC for LUKS

            # If using zswap enable lz4 compresstion
            if [ "ZZ${USE_ZSWAP}" != "ZZ" ]; then
                echo "lz4" >> /etc/modules-load.d/zfs-lz4.conf
            fi

        else
            # No swap partition - maybe using a zvol for swap
            echo "Enabling swap size ${SIZE_SWAP} on /dev/zvol/${POOLNAME}/ROOT/swap"
            mkswap -f /dev/zvol/${POOLNAME}/ROOT/swap
            if [ ${SIZE_SWAP} -ne 0 ] ; then
                echo "/dev/zvol/${POOLNAME}/ROOT/swap none swap discard,sw 0 0" >> /etc/fstab
            fi
        fi # HIBERNATE
    fi # WIPE_FRESH                         # <<<<<------------------------------------------------ WIPE_FRESH ------ ^^^^^


    # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    #   Configuration needed regardless of WIPE_FRESH
    # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    #
    # Potentially add delay before importing root pool in initramfs
    #
    if [ "${DELAY}" == "y" ] ; then
        echo "On systems with lots of disks, enumerating them can sometimes take a long"
        echo "time, which means the root disks may not have been enumerated before"
        echo "ZFS tries to import the root pool. That drops you to an initramfs prompt"
        echo "where you have to 'zfs import -N <root_pool> ; exit'"
        echo "So we set a delay in the initramfs to wait 25s before importing"
        echo "In /etc/default/zfs set ZFS_INITRD_POST_MODPROBE_SLEEP=10"
        echo "In /etc/default/zfs set ZFS_INITRD_PRE_MOUNTROOT_SLEEP=10"
        # First ensure the lines are there ... then ensure they have the right value
        grep -qxF 'ZFS_INITRD_POST_MODPROBE_SLEEP' /etc/default/zfs || echo "ZFS_INITRD_POST_MODPROBE_SLEEP='10'" >> /etc/default/zfs
        grep -qxF 'ZFS_INITRD_PRE_MOUNTROOT_SLEEP' /etc/default/zfs || echo "ZFS_INITRD_PRE_MOUNTROOT_SLEEP='10'" >> /etc/default/zfs
        sed -i "s/ZFS_INITRD_POST_MODPROBE_SLEEP=.*/ZFS_INITRD_POST_MODPROBE_SLEEP='10'/" /etc/default/zfs
        sed -i "s/ZFS_INITRD_PRE_MOUNTROOT_SLEEP=.*/ZFS_INITRD_PRE_MOUNTROOT_SLEEP='10'/" /etc/default/zfs
    fi


    echo "-------- installing basic packages ------------------------------------------"
    #
    # Install basic packages
    #
    apt-get -qq --no-install-recommends --yes install expect most vim-nox rsync whois gdisk \
        openssh-server avahi-daemon libnss-mdns

    #
    # Copy Avahi SSH service file into place
    #
    cp /usr/share/doc/avahi-daemon/examples/ssh.service /etc/avahi/services

    # For ZFSENC we need to set up a script and systemd unit to load the keyfile
    if [ "${DISCENC}" == "ZFSENC" ] ; then
        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /usr/bin/zfs-multi-mount.sh <<- 'EOF'
			#!/usr/bin/env bash
			# https://gbyte.dev/blog/unlock-mount-several-zfs-datasets-boot-single-passphrase

			PATH=/usr/bin:/sbin:/bin

			help() {
			    echo "Usage: $(basename "$0") [OPTION]... [SOURCE_POOL/DATASET]..."
			    echo
			    echo " -s, --systemd        use when within systemd context"
			    echo " -n, --no-mount       only load keys, do not mount datasets"
			    echo " -h, --help           show this help"
			    exit 0
			}

			for arg in "$@"; do
			  case $arg in
			  -s | --systemd)
			    systemd=1
			    shift
			    ;;
			  -n | --no-mount)
			    no_mount=1
			    shift
			    ;;
			  -h | --help) help ;;
			  -?*)
			    die "Invalid option '$1' Try '$(basename "$0") --help' for more information." ;;
			  esac
			done

			datasets=("$@")
			[ ${#datasets[@]} -eq 0 ] && mapfile -t datasets < <(zfs list -H -o name)
			attempt=0
			attempt_limit=3

			function ask_password {
			  if [ -v systemd ]; then
			    key=$(systemd-ask-password "Enter $dataset passphrase:" --no-tty) # While booting.
			  else
			    read -srp "Enter $dataset passphrase: " key ; echo # Other places.
			  fi
			}

			function load_key {
			  ! zfs list -H -o name | grep -qx "$dataset" && echo "ERROR: Dataset '$dataset' does not exist." && return 1
			  [[ $attempt == "$attempt_limit" ]] && echo "No more attempts left." && exit 1
			  keystatus=$(zfs get keystatus "$1" -H -o value)
			  echo "Testing $dataset status $keystatus"
			  [[ $keystatus != "unavailable" ]] && return 0
			  # Get the keylocation
			  key=$(zfs get keylocation "$1" -H -o value)
			  if [ "$key" != "prompt" ] ; then
			    if zfs load-key "$1" ; then
			      return 0
			    else
			      echo "Keyfile location invalid"
			      exit 1
			    fi
			  fi

			  if [ ! -v key ]; then
			    ((attempt++))
			    ask_password
			  fi
			  if ! echo "$key" | zfs load-key "$1"; then
			    unset key
			    load_key "$1"
			  fi
			  attempt=0
			  return 0
			}

			for dataset in "${datasets[@]}"; do
			  ! load_key "$dataset" && exit 1

			  # Mounting as non-root user on Linux is not possible,
			  # see https://github.com/openzfs/zfs/issues/10648.
			  [ ! -v no_mount ] && sudo zfs mount "$dataset" && echo "Dataset '$dataset' has been mounted."
			done

			unset key

			exit 0
		EOF
        chmod 755 /usr/bin/zfs-multi-mount.sh

        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /etc/systemd/system/zfs-load-key.service <<- EOF
			[Unit]
			Description=Import keys for all datasets
			DefaultDependencies=no
			Before=zfs-mount.service
			Before=systemd-user-sessions.service
			After=zfs-import.target
			### https://gbyte.dev/blog/unlock-mount-several-zfs-datasets-boot-single-passphrase
			### With emergency.target if the key cannot be loaded then boot will stop
			### This can happen when datasets have different keys, and one or more datasets
			### do not have the keys available (backups from remote systems etc.)
			### If this system does not have unknown keys, then OnFailure may be enabled
			### to ensure a proper stop when missing keys.
			# OnFailure=emergency.target

			### For now, we only unlock the home dataset which will unlock any child
			### datasets under it (root and ${USERNAME} by default from the ZFS-root.sh script)
			### If we do NOT specify the datasets here, then zfs-multi-mount.sh will try
			### to unlock ALl encrypted datasets it finds.  For those without keys this can
			### cause a delay until it times out.

			[Service]
			Type=oneshot
			RemainAfterExit=yes

			ExecStart=/usr/bin/zfs-multi-mount.sh --systemd ${POOLNAME}/home

			[Install]
			WantedBy=zfs-mount.service
		EOF
        systemctl enable zfs-load-key.service

    fi # if ZFSENC


    # Set hostkeys if defined via ZFS-root.conf
    if [[ -v HOST_ECDSA_KEY ]] ; then
        echo "${HOST_ECDSA_KEY}" > /etc/ssh/ssh_host_ecdsa_key
        echo "${HOST_ECDSA_KEY_PUB}" > /etc/ssh/ssh_host_ecdsa_key.pub
        chmod 600 /etc/ssh/ssh_host_ecdsa_key
        chmod 644 /etc/ssh/ssh_host_ecdsa_key.pub
    fi
    if [[ -v HOST_RSA_KEY ]] ; then
        echo "${HOST_RSA_KEY}" > /etc/ssh/ssh_host_rsa_key
        echo "${HOST_RSA_KEY_PUB}" > /etc/ssh/ssh_host_rsa_key.pub
        chmod 600 /etc/ssh/ssh_host_rsa_key
        chmod 644 /etc/ssh/ssh_host_rsa_key.pub
    fi
    if [[ -v HOST_ED25519_KEY ]] ; then
        echo "${HOST_ED25519_KEY}" > /etc/ssh/ssh_host_ed25519_key
        echo "${HOST_ED25519_KEY_PUB}" > /etc/ssh/ssh_host_ed25519_key.pub
        chmod 600 /etc/ssh/ssh_host_ed25519_key
        chmod 644 /etc/ssh/ssh_host_ed25519_key.pub
    fi

    # Setup system groups
    addgroup --system lpadmin
    addgroup --system sambashare

    apt-get -qq --yes dist-upgrade

    # Install acpi support
    if [ -d /proc/acpi ] ; then
        apt-get -qq --yes install acpi acpid
        service acpid stop
    fi # acpi

    # Nicer PS1 prompt
    # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
    cat >> /etc/bash.bashrc <<- EOF

		PS1="${debian_chroot:+($debian_chroot)}\[\$(tput setaf 2)\]\u@\[\$(tput bold)\]\[\$(tput setaf 5)\]\h\[\$(tput sgr0)\]\[\$(tput setaf 7)\]:\[\$(tput bold)\]\[\$(tput setaf 4)\]\w\[\$(tput setaf 7)\]\\$ \[\$(tput sgr0)\]"

		# https://unix.stackexchange.com/questions/99325/automatically-save-bash-command-history-in-screen-session
		PROMPT_COMMAND='history -a; history -n;'
	EOF

    # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
    cat >> /etc/skel/.bashrc <<- EOF

			PS1="${debian_chroot:+($debian_chroot)}\[\$(tput setaf 2)\]\u@\[\$(tput bold)\]\[\$(tput setaf 5)\]\h\[\$(tput sgr0)\]\[\$(tput setaf 7)\]:\[\$(tput bold)\]\[\$(tput setaf 4)\]\w\[\$(tput setaf 7)\]\\$ \[\$(tput sgr0)\]"

			# https://unix.stackexchange.com/questions/99325/automatically-save-bash-command-history-in-screen-session
			PROMPT_COMMAND='history -a; history -n;'
	EOF

    # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
    cat >> /etc/skel/.bash_aliases <<- EOF
			alias ls='ls --color=auto'
			alias l='ls -la'
			alias lt='ls -lat | head -25'
	EOF
    cp /etc/skel/.bash_aliases /root

    # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
    cat >> /root/.bashrc <<- "EOF"
		# PS1='\[\033[01;37m\]\[\033[01;41m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]$ '
		PS1='\[\033[01;37m\]\[\033[01;41m\]\u@\[\033[00m\]\[$(tput bold)\]\[$(tput setaf 5)\]\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]$ '

		# https://unix.stackexchange.com/questions/99325/automatically-save-bash-command-history-in-screen-session
		PROMPT_COMMAND='history -a; history -n;'
		HISTSIZE=5000
		export LC_ALL=en_US.UTF-8
		export LANG=en_US.UTF-8
		export LANGUAGE=en_US.UTF-8
	EOF


    # Create user - this create the mountpoint /home/${USERNAME}
    useradd -c "${UCOMMENT}" -p $(echo "${UPASSWORD}" | mkpasswd -m sha-512 --stdin) -M --home-dir /home/${USERNAME} --user-group --groups adm,cdrom,dip,lpadmin,plugdev,sambashare,sudo --shell /bin/bash ${USERNAME} > /dev/null 2>&1

    # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    #   Modifications to /boot/efi only when WIPE_FRESH
    # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    if [ "${WIPE_FRESH}" == "y" ] ; then     # <<<<<------------------------------------------------ WIPE_FRESH ------ VVVVV
        # Since /etc/skel/* files aren't copied, have to do it manually
        rsync -a /etc/skel/ /home/${USERNAME}
        mkdir /home/${USERNAME}/.ssh
        chmod 700 /home/${USERNAME}/.ssh

        if [ "${AUTHKEYS}" != "none" ] ; then
          for SSHKEY in ${AUTHKEYS} ; do
              FETCHKEY=$(wget --quiet -O- https://github.com/${SSHKEY}.keys)
              if [ ${#FETCHKEY} -ne 0 ] ; then
                  echo "####### Github ${SSHKEY} key #######" >> /home/${USERNAME}/.ssh/authorized_keys
                  echo "${FETCHKEY}" >> /home/${USERNAME}/.ssh/authorized_keys
                  echo "#" >> /home/${USERNAME}/.ssh/authorized_keys
              fi
          done
        fi

        if [[ -v SSHPUBKEY ]] ; then
            echo "####### ZFS-root.conf configured key #######" >> /home/${USERNAME}/.ssh/authorized_keys
            echo "${SSHPUBKEY}" >> /home/${USERNAME}/.ssh/authorized_keys
        fi

        chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}
    fi # WIPE_FRESH                         # <<<<<------------------------------------------------ WIPE_FRESH ------ ^^^^^

    # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    #   Configuration needed regardless of WIPE_FRESH
    # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    #
    # Set up Dropbear - after user is created with .ssh/authorized_keys
    # so those keys can be used in the initramfs
    # DROPBEAR can only be y if DISCENC is not NOENC (so encryption enabled)
    #
    mkdir -p /etc/cmdline.d /etc/zfsbootmenu/dracut.conf.d
    if [ "${DROPBEAR}" = "y" ] ; then
      echo "---------------------------------------------------"
      echo " Installing dropbear for remote unlocking"
      echo "---------------------------------------------------"

      apt-get -qq --yes install dracut-network dropbear-bin
      rm -rf /tmp/dracut-crypt-ssh && mkdir -p /tmp/dracut-crypt-ssh
      cd /tmp/dracut-crypt-ssh && curl -L https://github.com/dracut-crypt-ssh/dracut-crypt-ssh/tarball/master | tar xz --strip=1

      ##comment out references to /helper/ folder from module-setup.sh
      sed -i '/inst \"\$moddir/s/^\(.*\)$/#&/' /tmp/dracut-crypt-ssh/modules/60crypt-ssh/module-setup.sh
      cp -r /tmp/dracut-crypt-ssh/modules/60crypt-ssh /usr/lib/dracut/modules.d

      echo 'install_items+=" /etc/cmdline.d/dracut-network.conf "' >  /etc/zfsbootmenu/dracut.conf.d/dropbear.conf
      echo 'add_dracutmodules+=" crypt-ssh "'                      >> /etc/zfsbootmenu/dracut.conf.d/dropbear.conf
      # Have dracut use main user authorized_keys for access
      echo "dropbear_acl=/home/${USERNAME}/.ssh/authorized_keys"   >> /etc/zfsbootmenu/dracut.conf.d/dropbear.conf

      # With rd.neednet=1 it will fail to boot if no network available
      # This can be a problem with laptops and docking stations, if the dock
      # is not connected (no ethernet) it can fail to boot. Yay dracut.
      # Network really only needed for Dropbear/ssh access unlocking
      # Since we chose to use Dropbear, in this block set neednet=1
      echo 'ip=dhcp rd.neednet=1' > /etc/cmdline.d/dracut-network.conf
    else
      # Not using Dropbear, so set neednet=0
      echo 'install_items+=" /etc/cmdline.d/dracut-network.conf "' > /etc/zfsbootmenu/dracut.conf.d/network.conf
      echo 'ip=dhcp rd.neednet=0' > /etc/cmdline.d/dracut-network.conf
    fi # DROPBEAR

    # For ZFS encryption point to the /etc/zfs/zroot.rootkey files in the initramfs
    # These keys should have been copied into place above outside the chroot
    if [ "${DISCENC}" = "ZFSENC" ] ; then
        echo 'install_items+=" /etc/zfs/zroot.rootkey /etc/zfs/zroot.homekey"' >> /etc/dracut.conf.d/zfskey.conf
        if [ "${WIPE_FRESH}" == "y" ] ; then     # <<<<<------------------------------------------------ WIPE_FRESH ------ VVVVV
            zfs change-key -o keylocation=file:///etc/zfs/zroot.rootkey -o keyformat=passphrase ${POOLNAME}/ROOT
        fi # WIPE_FRESH                          # <<<<<------------------------------------------------ WIPE_FRESH ------ ^^^^^
    fi

    # For LUKS point to the larger 32-byte (zfs enc compatible) /etc/zfs/zroot.lukskey in the initramfs
    if [ "${DISCENC}" = "LUKS" ] ; then
        echo 'install_items+=" /etc/crypttab /etc/zfs/zroot.lukskey "' >> /etc/dracut.conf.d/zfskey.conf
    fi

    # Generate an initramfs
    dracut -v -f --regenerate-all

    if [ "${WIPE_FRESH}" == "y" ] ; then     # <<<<<------------------------------------------------ WIPE_FRESH ------ VVVVV
        if [ "${ZFSBOOTMENU_BINARY_TYPE}" = "LOCAL" ] ; then
            # generate-zbm only there if we built from scratch, not using downloaded image
            [ -e /usr/bin/generate-zbm ] && generate-zbm --debug
        else
            # Otherwise use syslinux-update.sh to create/update the syslinux.cfg
            [ -e /boot/efi/syslinux-update.sh ] && /boot/efi/syslinux-update.sh
        fi
    fi # WIPE_FRESH                         # <<<<<------------------------------------------------ WIPE_FRESH ------ ^^^^^


    #
    # Set up UEFI SecureBoot
    # Test above only allows y if /sys/firmware/efi exists
    #
    # If UEFI SecureBoot should be enabled - NOTE: only available for noble/24.04
    # Local building requires golang asciidoc-base pkgconf pkgconf-bin libpcsclite-dev
    # To build locally need libpcsclite-dev libpcsclite1 golang-go sbsigntool
    if [[ ! -v SECUREBOOT || "$SECUREBOOT" != "n" ]]; then
        if [[ -d /sys/firmware/efi && "${SUITE}" == "noble" ]] ; then
            # Create apt sources for sbctl
            curl -fsSL https://download.opensuse.org/repositories/home:jloeser:secureboot/xUbuntu_${SUITE_NUM}/Release.key | gpg --dearmor | sudo tee /usr/share/keyrings/secureboot.gpg > /dev/null

            # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
            cat > /etc/apt/sources.list.d/secureboot.sources <<- EOF
				X-Repolib-Name: SecureBoot
				Types: deb
				URIs: http://download.opensuse.org/repositories/home:/jloeser:/secureboot/xUbuntu_${SUITE_NUM}
				Signed-By: /usr/share/keyrings/secureboot.gpg
				Suites: /
				Enabled: yes
				Architectures: amd64
			EOF

            # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
            # We put /var/lib/sbctl into /boot/efi/sbctl, so need a config file to reflect that
            cat > /etc/sbctl <<- EOF
				keydir: /boot/efi/sbctl/keys
				guid: /boot/efi/sbctl/GUID
				files_db: /boot/efi/sbctl/files.json
				bundles_db: /boot/efi/sbctl/bundles.json
				landlock: true
				db_additions:
				- microsoft
				files:
				- path: /boot/vmlinuz-linux
				  output: /boot/vmlinuz-linux
				- path: /efi/EFI/Linux/arch-linux.efi
				  output: /efi/EFI/Linux/arch-linux.efi
				keys:
				  pk:
				    privkey: /boot/efi/sbctl/keys/PK/PK.key
				    pubkey: /boot/efi/sbctl/keys/PK/PK.pem
				    type: file
				  kek:
				    privkey: /boot/efi/sbctl/keys/KEK/KEK.key
				    pubkey: /boot/efi/sbctl/keys/KEK/KEK.pem
				    type: file
				  db:
				    privkey: /boot/efi/sbctl/keys/db/db.key
				    pubkey: /boot/efi/sbctl/keys/db/db.pem
				    type: file
				- path: /boot/efi/EFI/refind/refind_x64.efi
				  output: /boot/efi/EFI/refind/refind_x64.efi
				- path: /boot/efi/EFI/tools/memtest86/memtest86.efi
				  output: "/boot/efi/EFI/tools/memtest86/memtest86.efi
				- path: /boot/efi/EFI/tools/shellx64.efi
				  output: "/boot/efi/EFI/tools/shellx64.efi
				- path: /boot/efi/EFI/zfsbootmenu/vmlinuz-bootmenu
				  output: "/boot/efi/EFI/zfsbootmenu/vmlinuz-bootmenu
				- path: /boot/efi/EFI/zfsbootmenu/zfsbootmenu.efi
				  output: "/boot/efi/EFI/zfsbootmenu/zfsbootmenu.efi
			EOF

            apt-get -qq update
            apt-get -qq --yes --no-install-recommends install systemd-boot-efi
            apt-get -qq --yes --no-install-recommends install sbctl systemd-ukify

            if [ "${WIPE_FRESH}" == "y" ] ; then     # <<<<<------------------------------------------------ WIPE_FRESH ------ VVVVV
                # Only need to create the efi image if we installed zfsbootmenu as the
                # kernel/initramfs setup or built locally
                if [ "${ZFSBOOTMENU_BINARY_TYPE}" != "EFI" ] ; then
                    # Create zfsbootmenu efi bundle - use the same name as the EFI image from
                    # when we installed zfsbootmenu above
                    /usr/bin/ukify build \
                        --linux=/boot/efi/EFI/zfsbootmenu/vmlinuz-bootmenu \
                        --initrd=/boot/efi/EFI/zfsbootmenu/initramfs-bootmenu.img \
                        --output=/boot/efi/EFI/zfsbootmenu/zfsbootmenu.efi \
                        --cmdline='quiet rw'
                fi

                # Initialize sbctl and sign all the things
                # sbctl setup --setup --config /etc/sbctl/sbctl.conf
                /usr/sbin/sbctl create-keys
                /usr/sbin/sbctl enroll-keys --microsoft
                /usr/sbin/sbctl sign -s /boot/efi/EFI/refind/refind_x64.efi
                /usr/sbin/sbctl sign -s /boot/efi/EFI/tools/memtest86/memtest86.efi
                /usr/sbin/sbctl sign -s /boot/efi/EFI/tools/shellx64.efi
                /usr/sbin/sbctl sign -s /boot/efi/EFI/zfsbootmenu/zfsbootmenu.efi
                if [ "${ZFSBOOTMENU_BINARY_TYPE}" != "EFI" ] ; then
                    /usr/sbin/sbctl sign -s /boot/efi/EFI/zfsbootmenu/vmlinuz-bootmenu
                fi
            fi # WIPE_FRESH                         # <<<<<------------------------------------------------ WIPE_FRESH ------ ^^^^^

            # Setup systemd path watch to update zfsbootmenu efi when zfsbootmenu is updated
            # This way when you update ZBM, it will automagically update and sign the EFI image
            # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
            cat > /etc/systemd/system/zfsbootmenu-sign-efi.service <<- EOF
				[Unit]
				Description=Sign ZFSBootmenu EFI image bundle

				[Service]
				Type=oneshot
				ExecStart=/usr/sbin/sbctl sign -s /boot/efi/EFI/zfsbootmenu/zfsbootmenu.efi
			EOF

            # Watch the zfsbootmenu.efi image for changes
            # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
            cat > /etc/systemd/system/zfsbootmenu-update-efi-image.path <<- EOF
				[Unit]
				Description=ZFSBootmenu kernel changed, rebuild EFI image bundle

				[Path]
				PathChanged=/boot/efi/EFI/zfsbootmenu/zfsbootmenu.efi
				Unit=zfsbootmenu-sign-efi.service

				[Install]
				WantedBy=multi-user.target
				WantedBy=system-update.target
			EOF

            # Rebuild the zfsbootmenu.efi image if the kernel or initramfs change
            # We re-sign the kernel and initramfs here because there is another watch
            # above that handles signing the efi image
            # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
            cat > /etc/systemd/system/zfsbootmenu-update@.service <<- EOF
				[Unit]
				Description=Update ZFSBootmenu EFI image bundle

				[Service]
				Type=oneshot
				# Sleep for 5secs to allow both kernel/initramfs files to be created
				ExecStart=/usr/bin/sleep 5
				ExecStart=/usr/bin/ukify build --linux=/boot/efi/EFI/zfsbootmenu/vmlinuz-bootmenu --initrd=/boot/efi/EFI/zfsbootmenu/initramfs-bootmenu.img --output=/boot/efi/EFI/zfsbootmenu/zfsbootmenu.efi --cmdline='quiet rw'
				ExecStart=/usr/sbin/sbctl sign -s /boot/efi/EFI/zfsbootmenu/vmlinuz-bootmenu
			EOF

            # Watch the zfsbootmenu kernel for changes
            # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
            cat > /etc/systemd/system/zfsbootmenu-update-kernel-bootmenu.path <<- EOF
				[Unit]
				Description=ZFSBootmenu kernel changed, rebuild EFI image bundle

				[Path]
				PathChanged=/boot/efi/EFI/zfsbootmenu/vmlinuz-bootmenu
				Unit=zfsbootmenu-update@vmlinuz-bootmenu.service

				[Install]
				WantedBy=multi-user.target
				WantedBy=system-update.target
			EOF

            # Watch the zfsbootmenu initramfs for changes
            # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
            cat > /etc/systemd/system/zfsbootmenu-update-initramfs-bootmenu.path <<- EOF
				[Unit]
				Description=ZFSBootmenu initramfs changed, rebuild EFI image bundle

				[Path]
				PathChanged=/boot/efi/EFI/zfsbootmenu/initramfs-bootmenu.img
				Unit=zfsbootmenu-update@initramfs-bootmenu.service

				[Install]
				WantedBy=multi-user.target
				WantedBy=system-update.target
			EOF

            # Re-sign the rEFInd efi binary if required
            cat > /etc/systemd/system/refind-update.service <<- EOF
				[Unit]
				Description=Re-sign rEFInd binary

				[Service]
				Type=oneshot
				ExecStart=/usr/sbin/sbctl sign -s /boot/efi/EFI/refind/refind_x64.efi
			EOF

            # Watch rEFInd for changes
            # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
            cat > /etc/systemd/system/refind-update.path <<- EOF
				[Unit]
				Description=rEFInd binary changed, re-sign

				[Path]
				PathChanged=/boot/efi/EFI/refind/refind_x64.efi
				Unit=refind-update.service

				[Install]
				WantedBy=multi-user.target
				WantedBy=system-update.target
			EOF

            if [ "${AUTOSIGN}" = "y" ] ; then
                systemctl enable zfsbootmenu-update-efi-image.path
                systemctl enable zfsbootmenu-update-kernel-bootmenu.path
                systemctl enable zfsbootmenu-update-initramfs-bootmenu.path
                systemctl enable refind-update.path
            fi
        fi # firmware & SUITE
    fi # SecureBoot


    # Allow read-only zfs commands with no sudo password
    cat /etc/sudoers.d/zfs | sed -e 's/#//' > /etc/sudoers.d/zfsALLOW

    # Configure google authenticator if we have a config
    if [ "${GOOGLE}" = "y" ]; then
        apt-get -qq --no-install-recommends --yes install python3-qrcode qrencode libpam-google-authenticator
        if [ "${WIPE_FRESH}" == "y" ] ; then     # <<<<<------------------------------------------------ WIPE_FRESH ------ VVVVV
            cp /root/google_auth.txt /home/${USERNAME}/.google_authenticator
            chmod 400 /home/${USERNAME}/.google_authenticator
            chown ${USERNAME}:${USERNAME} /home/${USERNAME}/.google_authenticator
        fi # WIPE_FRESH                          # <<<<<------------------------------------------------ WIPE_FRESH ------ ^^^^^

        # TODO: parameterize the nullok bits
        # Set pam to use google authenticator for ssh
        # NOTE: add nullok to end of line to allow regular logins if ~/.google_authenticator does not exist
        echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd
        # If using nullok, then add this line
        # echo "auth required pam_permit.so" >> /etc/pam.d/sshd

        # Tell sshd to use google_authenticator
        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /etc/ssh/sshd_config.d/70-google_auth.conf < EOF
			# For google authenticator
			#
			KbdInteractiveAuthentication yes
		EOF

        # Instruct PAM to prompt for a password by default
        sed -i "s/^#.*@include common-auth/@include common-auth/" /etc/pam.d/sshd

        # Enable this to force use of token always, even with SSH key
        # sed -i "s/.*PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config
    fi # GOOGLE_AUTH


    # Add IP address(es) to main tty issue
    # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
    cat > /etc/systemd/system/showip.service <<- EOF
		[Unit]
		Description=Add IP address(es) to /etc/issue
		After=network-online.target

		[Service]
		Type=oneshot
		ExecStart=/usr/local/bin/showip.sh
		RemainAfterExit=true

		[Install]
		WantedBy=multi-user.target
	EOF

    # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
    cat > /usr/local/bin/showip.sh <<- 'EOF'
		#!/bin/bash

		# Creates a normal /etc/issue file but populates the bottom with a list
		# of all network interfaces found. The /4{} gets filled in with IPv4 addresses
		# as they are obtained, so the splash screen is always live with correct info
		# Exclude lo, virtual and docker interfaces - they're just messy

		echo -e "$(lsb_release -d -s) \\\n \l\n" > /etc/issue
		echo "$(ls -1 /sys/class/net | grep -E -v 'lo|vir|docker|tap|veth|br-|zt?' | xargs -I {} echo '   {} : \4{{}}')" >> /etc/issue
		echo "" >> /etc/issue
	EOF

    chmod +x /usr/local/bin/showip.sh
    systemctl enable showip.service

    #-----------------------------------------------------------------------------
    if [ "${ZREPL}" = "y" ]; then
        if [ ! -d /etc/apt/keyrings ] ; then
            mkdir -p /etc/apt/keyrings
        fi

        # Install zrepl for zfs snapshot management
        zrepl_apt_key_url=https://zrepl.cschwarz.com/apt/apt-key.asc
        zrepl_apt_key_dst=/etc/apt/keyrings/zrepl.gpg
        curl -fsSL "$zrepl_apt_key_url" | tee | gpg --dearmor | tee "$zrepl_apt_key_dst" > /dev/null

        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /etc/apt/sources.list.d/zrepl.sources <<- EOF
			Architectures: amd64
			Components: main
			Enabled: yes
			X-Repolib-Name: zrepl ZFS replication
			Signed-By: ${zrepl_apt_key_dst}
			Suites: ${SUITE}
			Types: deb
			URIs: https://zrepl.cschwarz.com/apt/ubuntu
		EOF

        apt-get -qq update
        apt-get -qq --yes install zrepl
        systemctl stop zrepl
        mv /etc/zrepl/zrepl.yml /etc/zrepl/zrepl.yml.BAK

        # Set the main root dataset snapshot threshold to 120mb
        zfs set com.zrepl:snapshot-threshold=120000000 ${POOLNAME}/ROOT/${SUITE}

        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /etc/zrepl/zrepl.yml <<- EOF
			global:
			  logging:
			    # use syslog instead of stdout because it makes journald happy
			    - type: syslog
			      format: human
			      level: warn

			jobs:
			  - name: snaproot
			    type: snap
			    filesystems: {
			        "${POOLNAME}/ROOT/${SUITE}<": true,
			    }
			    # create snapshots with prefix 'zrepl_' every 15 minutes
			    snapshotting:
			      type: periodic
			      interval: 15m
			      # "human" format has colons in the time, makes selecting/copying a snapshot
			      # name a hassle.  Using dashes makes it a single double-click of the mouse
			      timestamp_format: "2006-01-02_15-04-05"
			      prefix: zrepl_
			      hooks:
			        # threshold script only allows snaps if amount of data written is greater
			        # than the threshold value in dataset property com.zrepl:snapshot-threshold
			        # zfs set com.zrepl:snapshot-threshold=10000000 ${POOLNAME}/ROOT/${SUITE}
			        - type: command
			          path: /usr/local/bin/zrepl_threshold_check.sh
			          err_is_fatal: true
			          filesystems: {
			            "${POOLNAME}/ROOT/${SUITE}<": true,
			          }
			    pruning:
			      keep:
			      # fade-out scheme for snapshots starting with 'zrepl_'
			      # - keep all created in the last hour
			      # - then destroy snapshots such that we keep 24 each 1 hour apart
			      # - then destroy snapshots such that we keep 14 each 1 day apart
			      # - then destroy all older snapshots
			      - type: grid
			        grid: 1x1h(keep=all) | 24x1h | 14x1d
			        regex: "^zrepl_.*"
			      # Only keep the last 10 of the auto snaps by apt
			      - type: last_n
			        count: 10
			        regex: "^apt_.*"
			      # keep all base or desktop install snapshots
			      - type: regex
			        regex: "^(base_install|desktop_install)"
			      # keep all snapshots that don't have the 'zrepl_' or 'apt_' prefix
			      # Note: apt snapshots are governed by the apt last_n policy above
			      - type: regex
			        negate: true
			        regex: "^(zrepl|apt)_.*"

			  - name: snaphome
			    type: snap
			    filesystems: {
			        "${POOLNAME}/home/${USERNAME}<": true,
			    }
			    # create snapshots with prefix 'zrepl_' every 15 minutes
			    snapshotting:
			      type: periodic
			      interval: 15m
			      timestamp_format: human
			      prefix: zrepl_
			    pruning:
			      keep:
			      - type: grid
			        grid: 1x1h(keep=all) | 24x1h | 30x1d
			        regex: "^zrepl_.*"
			      # keep all base or desktop installs
			      - type: regex
			        regex: "^(base_install|desktop_install)"
			      # keep all snapshots that don't have the 'zrepl_' or 'apt_' prefix
			      # Note: apt snapshots are governed by the apt last_n policy above
			      - type: regex
			        negate: true
			        regex: "^zrepl_.*"
		EOF

        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /usr/local/bin/zrepl_threshold_check.sh <<- 'EOF'
			#!/usr/bin/env bash
			set -e

			# Checks the data-written threshold of a zfs dataset for use with zrepl
			# Returns 0 if over threshold so should be snapshot'd
			# Returns 255 if amount written has not reached threshold
			# If no threshold property set in dataset default yes, take snapshot

			# Set threshold in bytes like this :
			# zfs set com.zrepl:snapshot-threshold=6000000 pool/dataset

			WRITTEN=$(zfs get -Hpo value written ${ZREPL_FS})
			THRESH=$(zfs get -Hpo value com.zrepl:snapshot-threshold ${ZREPL_FS})

			[ "$ZREPL_DRYRUN" = "true" ] && DRYRUN="echo DRYRUN (WRITTEN ${WRITTEN} THRESH ${THRESH}) : "

			pre_snapshot() {
			    echo -n "pre_snap "
			    $DRYRUN date

			    if [ "$ZREPL_DRYRUN" != "true" ] ; then
			        # [[ $( $(zfs get -Hpo value written ${ZREPL_FS}) -gt ($(zfs get -Hpo value com.zrepl:snapshot-threshold ${ZREPL_FS}) +0)) ]] && RC=0 || RC=255
			        if [ "${THRESH}" = "-" ]; then
			            RC=0
			        elif [ ${WRITTEN} -gt ${THRESH} ] ; then
			            RC=0
			        else
			            printf '%s dataset has written %s, NOT over threshold %s, skipping\n' "$ZREPL_FS" "$WRITTEN" "$THRESH"
			            RC=255
			        fi
			    fi
			}

			post_snapshot() {
			    echo -n "post_snap "
			    $DRYRUN date
			}

			case "$ZREPL_HOOKTYPE" in
			    pre_snapshot|post_snapshot)
			        "$ZREPL_HOOKTYPE"
			        ;;
			    *)
			        printf 'Unrecognized hook type: %s\n' "$ZREPL_HOOKTYPE"
			        exit 255
			        ;;
			esac

			exit $RC
		EOF
        chmod +x /usr/local/bin/zrepl_threshold_check.sh
    fi
    #-----------------------------------------------------------------------------

    # Set apt/dpkg to automagically snap the system datasets on install/remove
    # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
    cat > /etc/apt/apt.conf.d/30pre-snap <<- EOF
		# Snapshot main dataset before installing or removing packages
		# We use a DATE variable to ensure all snaps have SAME date
		# Use df to find root dataset

		# Dpkg::Pre-Invoke { "export DATE=\$(/usr/bin/date +%F-%H%M%S) ; ${ZFSLOCATION} snap \$(${ZFSLOCATION} list -o name | /usr/bin/grep -E 'ROOT/.*$' | sort | head -1)@apt_\${DATE}"; };
		Dpkg::Pre-Invoke { "export DATE=\$(/usr/bin/date +%F-%H%M%S) ; ${ZFSLOCATION} snap \$(/usr/bin/df | /usr/bin/grep -E '/\$' | /usr/bin/cut -d' ' -f1)@apt_\${DATE}"; };
	EOF

    zfs snapshot ${POOLNAME}/ROOT/${SUITE}@base_install

    # Optionally create a clone of the new system as a rescue dataset.
    # This will show up in zfsbootmenu as a bootable dataset just in
    # case the main dataset gets corrupted during an update or something.
    # As the system is upgraded, the clone should periodically be replaced
    # with a clone of a newer snapshot.
    if [ "${RESCUE}" = "y" ]; then
        zfs clone ${POOLNAME}/ROOT/${SUITE}@base_install ${POOLNAME}/ROOT/${SUITE}_rescue_base
        zfs set canmount=noauto ${POOLNAME}/ROOT/${SUITE}_rescue_base
        zfs set mountpoint=/ ${POOLNAME}/ROOT/${SUITE}_rescue_base
    fi

    # Install main ubuntu gnome desktop, plus maybe HWE packages
    if [ "${GNOME}" = "y" ] ; then
        # NOTE: bionic has an xserver-xorg-hwe-<distro> package, focal and above do NOT
        case ${SUITE} in
            focal | jammy | noble | plucky | questing)
                # Don't install kdump-tools
                cat > /tmp/kdump-selections <<- EOF
					# Should kdump-tools be enabled by default?
					kdump-tools     kdump-tools/use_kdump   boolean false
				EOF
                cat /tmp/kdump-selections | debconf-set-selections
                apt-get -qq --yes install ubuntu-desktop vulkan-tools
                ;;
            bionic)
                apt-get -qq --yes install ubuntu-desktop xserver-xorg${HWE} vulkan-tools
                ;;
            *)
                # Default to not specifying hwe xorg just in case
                apt-get -qq --yes install ubuntu-desktop vulkan-tools
                ;;
        esac
    fi # GNOME

    # Install main ubuntu kde desktop
    if [ "${KDE}" = "y" ] ; then
        # Don't install kdump-tools
        cat > /tmp/kdump-selections <<- EOF
			# Should kdump-tools be enabled by default?
			kdump-tools     kdump-tools/use_kdump   boolean false
		EOF
        cat /tmp/kdump-selections | debconf-set-selections
        apt-get -qq --yes install kde-full vulkan-tools
    fi # KDE

    # Install main ubuntu xfce4 desktop
    if [ "${XFCE}" = "y" ] ; then
        # Don't install kdump-tools
        cat > /tmp/kdump-selections <<- EOF
			# Should kdump-tools be enabled by default?
			kdump-tools     kdump-tools/use_kdump   boolean false
		EOF
        cat /tmp/kdump-selections | debconf-set-selections
        apt-get -qq --yes install xfce4 xfce4-goodies vulkan-tools
    fi # XFCE

    # Install main Neon KDE desktop
    if [ "${NEON}" = "y" ] ; then
        # Don't install kdump-tools
        cat > /tmp/kdump-selections <<- EOF
			# Should kdump-tools be enabled by default?
			kdump-tools     kdump-tools/use_kdump   boolean false
		EOF
        cat /tmp/kdump-selections | debconf-set-selections
        # Ensure the keyrings dir exists - it should, but be sure
        mkdir -p /usr/share/keyrings
        wget -qO /usr/share/keyrings/neon.key 'https://archive.neon.kde.org/public.key'
        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /etc/apt/sources.list.d/neon.list <<- EOF
			deb [signed-by=/usr/share/keyrings/neon.key] http://archive.neon.kde.org/user/ ${SUITE} main
			deb-src [signed-by=/usr/share/keyrings/neon.key] http://archive.neon.kde.org/user/ ${SUITE} main
		EOF

        # Pin base-files to not install the Neon version
        # This prevents the install identifying as Neon, and stops problems with programs that this confuses
        # eg the Docker install script
        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /etc/apt/preferences.d/99block-neon <<- EOF
			Package: base-files
			Pin: origin archive.neon.kde.org
			Pin-Priority: 1
		EOF

        # Use real firefox, not that snap crap
        apt-add-repository --yes --update ppa:mozillateam/ppa
        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /etc/apt/preferences.d/99mozillateam <<- EOF
			Package: firefox
			Pin: origin ppa.launchpadcontent.net
			Pin-Priority: 700
		EOF

        # neon desktop includes encfs, which prompts that it's not secure,
        # requiring someone to hit <enter> - this should bypass that
        # Also, pre-select the sddm display manager login
        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /tmp/neon.debconf <<- EOF
			encfs  encfs/security-information boolean true
			encfs  encfs/security-information seen true
			gdm3   shared/default-x-display-manager select sddm
			sddm   shared/default-x-display-manager select sddm
			kdm    shared/default-x-display-manager select sddm
		EOF
        cat /tmp/neon.debconf | debconf-set-selections

        apt-get -qq update
        apt-get -qq --yes install neon-desktop firefox vulkan-tools packagekit-tools
    fi # NEON

    if [ "${GNOME}" = "y" ] || [ "${KDE}" = "y" ] || [ "${NEON}" = "y" ] || [ "${XFCE}" = "y" ] ; then
        # Ensure networking is handled by NetworkManager
        sed -i 's/networkd/NetworkManager/' /etc/netplan/01_netcfg.yaml

        # NOTE: Using <<- EOF so it wills strip leading TAB chars
        #       MUST be TAB chars, not spaces
        cat > /etc/NetworkManager/conf.d/10-globally-managed-devices.conf <<- EOF
			[keyfile]
			unmanaged-devices=*,except:type:wifi,except:type:wwan,except:type:ethernet
		EOF

        # Check for Nvidia graphics - if so, install from the ppa:graphics-drivers/ppa
        # The NVIDIA var should be set to the appropriate version from the menu query
        if [ "${NVIDIA}" != "none" ] ; then
            apt-add-repository --yes --update ppa:graphics-drivers/ppa
            apt-get -qq --yes install nvidia-driver-${NVIDIA} libxnvctrl0
        fi

        ####
        #### Install seems to bork when done under livecd
        ####
        ####  # Install DisplayLink drivers
        ####  # http://www.synaptics.com/products/displaylink-graphics/downloads/ubuntu
        ####  # We need the kernel headers for RUNNING kernel to install displaylink stuff
        ####  # Running kernel from livecd - kernel installed here is likely newer
        ####  # As of this writing, livecd is 5.15.0-43, while latest is 5.15.0-60
        ####  apt-get -qq --yes install cpp-12 dctrl-tools fakeroot gcc-12 libasan8 libfakeroot libgcc-12-dev libtsan2 libdrm-dev libpciaccess-dev dkms linux-headers-$(uname -r) build-essential
        ####  # Install HWE variant if it exists - OK to fail
        ####  apt-get -qq --yes install linux-headers-$(uname -r)${HWE}
        ####  wget -O /tmp/DisplayLink-5.6.1.zip http://www.synaptics.com/sites/default/files/exe_files/2022-08/DisplayLink%20USB%20Graphics%20Software%20for%20Ubuntu5.6.1-EXE.zip
        ####  mkdir /usr/local/share/DisplayLink-5.6.1
        ####  cd /usr/local/share/DisplayLink-5.6.1
        ####  unzip /tmp/DisplayLink-5.6.1.zip
        ####  ./displaylink-driver-5.6.1-59.184.run --accept --noprogress --nox11

    fi # GNOME KDE NEON XFCE

    # Enable hibernate in upower and logind if desktop is installed
    if [ -d /etc/polkit-1/localauthority/50-local.d ] ; then
        # NOTE: heredoc using TABS - be sure to use TABS if you make any changes
        cat > /etc/polkit-1/localauthority/50-local.d/com.ubuntu.enable-hibernate.pkla <<- EOF
			[Re-enable hibernate by default in upower]
			Identity=unix-user:*
			Action=org.freedesktop.upower.hibernate
			ResultActive=yes

			[Re-enable hibernate by default in logind]
			Identity=unix-user:*
			Action=org.freedesktop.login1.hibernate;org.freedesktop.login1.handle-hibernate-key;org.freedesktop.login1;org.freedesktop.login1.hibernate-multiple-sessions;org.freedesktop.login1.hibernate-ignore-inhibit
			ResultActive=yes
		EOF
    fi # Hibernate

    # Install Sound Open Firmware binaries if requested
    # Ugh - need to hard-code for now - repo is a bit of a mess with installs
    if [ "${SOF}" = "y" ]; then
        # Ensure we have the tools we need
        apt-get -qq --yes install rsync git
        # git clone https://github.com/thesofproject/sof-bin.git /usr/local/share/sof-project
        # cd /usr/local/share/sof-project
        # LATEST=$(ls -dC1 v* | tail -1)
        # LATESTBASE=$(basename $LATEST .x)
        # LATESTFILE=$(ls -C1 ${LATEST}/${LATESTBASE}* | tail -1)
        # ./install.sh $LATESTFILE

        wget --quiet -O /tmp/sof-bin-${SOF_VERSION}.tar.gz https://github.com/thesofproject/sof-bin/releases/download/v${SOF_VERSION}/sof-bin-${SOF_VERSION}.tar.gz
        tar -C /usr/local/share/ -xf /tmp/sof-bin-${SOF_VERSION}.tar.gz
        chown -R ${USERNAME}:${USERNAME} /usr/local/share/sof-bin-${SOF_VERSION}
        cd /usr/local/share/sof-bin-${SOF_VERSION}
        ./install.sh
    fi # Sound Open Firmware

    # Snapshot the clean desktop(s) after base install
    if [ "${GNOME}" = "y" ] || [ "${KDE}" = "y" ] || [ "${NEON}" = "y" ] || [ "${XFCE}" = "y" ] ; then
        zfs snapshot ${POOLNAME}/ROOT/${SUITE}@desktop_install

        # Optionally create a clone of the new system with desktop as a rescue dataset.
        # This will show up in zfsbootmenu as a bootable dataset just in
        # case the main dataset gets corrupted during an update or something.
        # As the system is upgraded, the clone should periodically be replaced
        # with a clone of a newer snapshot.
        if [ "${RESCUE}" = "y" ]; then
            zfs clone ${POOLNAME}/ROOT/${SUITE}@desktop_install ${POOLNAME}/ROOT/${SUITE}_rescue_desktop
            zfs set canmount=noauto ${POOLNAME}/ROOT/${SUITE}_rescue_desktop
            zfs set mountpoint=/ ${POOLNAME}/ROOT/${SUITE}_rescue_desktop
        fi
    fi # GNOME

    if [ "${WIPE_FRESH}" == "y" ] ; then
        umount /boot/efi
    fi

    # End of Setup.sh
__EOF__
} # build_setup()


## -------------------------------------------------------------------------------------------------------
## Original order of non-functions script
## preflight() {
## wipe_fresh() {
## setup_cacher() {
## query_user() {
## select_disks() {
## select_encryption() {
## query_install_options() {
## query_nvidia() {
## query_google_auth() {
## query_ssh_auth() {
## query_swap() {
## query_suite() {
## query_secureboot() {
## show_options() {
## log_options() {
## install_zfs() {
## find_zfs_config() {
## partition_disks() {
## setup_swap_partition() {
## luks_encrypt_root() {
## create_root_pool() {
## create_zfs_datasets() {
## install_debootstrap() {
## setup_boot_partition() {
## setup_network_config() {
## setup_apt_config() {
## setup_googleauth_refind() {
## prep_setup() {
## build_setup() {
## -------------------------------------------------------------------------------------------------------

# Set up initial conditions
preflight "$@"

# Are we wiping and installing a full fresh system ?
wipe_fresh "$@"

# Query user/configfile for general settings
if [ "${WIPE_FRESH}" == "y" ] ; then
    # Setup proxy to apt-cacher if available
    setup_cacher
    query_user
fi

# Which Ubuntu are we installing ?
query_suite

# Are we setting up secureboot ?
# Select which disks to install to if wiping fresh
if [ "${WIPE_FRESH}" == "y" ] ; then
    query_secureboot    # NOTE: sbctl only available for noble/24.04
    select_disks "$@"
fi

# Choose encryption
select_encryption

# Query for install options
query_install_options
# zrepl has no release for 25.04/plucky or 25.10/questing yet
[ "${SUITE}" == "plucky" ] || [ "${SUITE}" == "questing" ] && ZREPL=n

query_nvidia
query_google_auth
query_ssh_auth
query_swap

if [[ -v PACKERCI ]] ; then
    show_options
fi

# Log everything we do
rm -f /root/ZFS-setup.log
exec > >(tee -a "/root/ZFS-setup.log") 2>&1
[[ -v DEBUG ]] && set -x
[[ -v PACKERCI ]] && set -x

log_options

# Assuming if wiping fresh we need to install ZFS in liveCD
# If not wiping fresh then we should be running on an existing system with
# ZFS and the pool and datasets
apt-get -qq --no-install-recommends --yes install debootstrap gdisk dosfstools mdadm
if [ "${WIPE_FRESH}" == "y" ] ; then
    install_zfs
    partition_disks
    setup_swap_partition
    luks_encrypt_root
    create_root_pool
    create_zfs_datasets
else
    # If not wiping fresh, just creating a new ROOT dataset, we need to find
    # the current ZFS config.  hostname, poolname, username
    find_zfs_config

    # Actual dataset for suite we are installing now
    # COMPLETELY clear out build dir
    rm -rf ${ZFSBUILD}
    mkdir -p ${ZFSBUILD}
    zfs create -o canmount=noauto -o mountpoint=${ZFSBUILD} ${POOLNAME}/ROOT/${SUITE}
    zfs mount ${POOLNAME}/ROOT/${SUITE}
    # For a plain root dataset need devices available for debootstrap
    zfs set devices=on ${POOLNAME}/ROOT/${SUITE}
fi

# debootstrap the new root filesystem
install_debootstrap

# Set up the boot partition, possibly mdadm mirrored
if [ "${WIPE_FRESH}" == "y" ] ; then
    setup_boot_partition
else
    # Not wiping fresh - just use existing fstab which has /boot/efi mount in it
    # Also need the encryption keys from existing setup
    mkdir -p ${ZFSBUILD}/etc
    mkdir -p ${ZFSBUILD}/boot/efi
    cp /etc/fstab ${ZFSBUILD}/etc/fstab
fi

# Grab config files from exiting setup if NOT wipe_fresh
if [ "${WIPE_FRESH}" == "n" ] ; then
    mkdir -p ${ZFSBUILD}/etc/zfs
    [ -e /etc/zfs/zroot.lukskey ] && cp /etc/zfs/zroot.lukskey ${ZFSBUILD}/etc/zfs/zroot.lukskey
    [ -e /etc/zfs/zroot.rootkey ] && cp /etc/zfs/zroot.rootkey ${ZFSBUILD}/etc/zfs/zroot.rootkey
    [ -e /etc/zfs/zroot.homekey ] && cp /etc/zfs/zroot.homekey ${ZFSBUILD}/etc/zfs/zroot.homekey
    if [ "${DISCENC}" == "LUKS" ] ; then
        [ -e /etc/crypttab ] && cp /etc/crypttab ${ZFSBUILD}/etc/crypttab
        [ -e /etc/zfsbootmenu/dracut.conf.d/luks_zbm.conf ] && cp /etc/zfsbootmenu/dracut.conf.d/luks_zbm.conf ${ZFSBUILD}/etc/zfsbootmenu/dracut.conf.d/
        mkdir -p ${ZFSBUILD}/usr/local/bin
        [ -e /usr/local/bin/zfsbootmenu_luks_unlock.sh ] && cp /usr/local/bin/zfsbootmenu_luks_unlock.sh ${ZFSBUILD}/usr/local/bin/
        if [ "${HIBERNATE}" = "y" ] ; then
            [ -e /etc/dracut.conf.d/resume-swap-uuid.conf ] && cp /etc/dracut.conf.d/resume-swap-uuid.conf ${ZFSBUILD}/etc/dracut.conf.d
        fi
    fi
fi

# Set up network config and apt sources
setup_network_config
setup_apt_config

# Copy google auth config and rEFInd images
setup_googleauth_refind

# Create the Setup.sh for chroot
prep_setup "$@"
build_setup "$@"

chmod +x ${ZFSBUILD}/root/Setup.sh

# Bind mount virtual filesystem, create Setup.sh, then chroot
mount -t proc /proc ${ZFSBUILD}/proc
mount -t sysfs sys  ${ZFSBUILD}/sys
mount -B /dev  ${ZFSBUILD}/dev
mount -t devpts pts ${ZFSBUILD}/dev/pts

# chroot and set up system
# chroot ${ZFSBUILD} /bin/bash --login -c /root/Setup.sh
unshare --mount --fork chroot ${ZFSBUILD} /bin/bash --login -c /root/Setup.sh $1

# Remove any lingering crash reports
rm -f ${ZFSBUILD}/var/crash/*

umount -n ${ZFSBUILD}/{dev/pts,dev,sys,proc}

# Copy setup log and chroot Setup.sh to originating system (livecd or local /root dir)
DATETIME=$(date +%F-%H-%M-%S)
# Copy setup log and chroot Setup.sh to local install dir
cp /root/ZFS-setup.log       ZFS-${MYHOSTNAME}-${SUITE}-wipe_${WIPE_FRESH}-${DATETIME}.log
cp ${ZFSBUILD}/root/Setup.sh ZFS-${MYHOSTNAME}-${SUITE}-wipe_${WIPE_FRESH}-${DATETIME}.chroot.sh

if [ "${WIPE_FRESH}" == "y" ] ; then
    # Copy setup log and chroot Setup.sh to built system
    cp /root/ZFS-setup.log       ${ZFSBUILD}/home/${USERNAME}/ZFS-${MYHOSTNAME}-${SUITE}-wipe_${WIPE_FRESH}-${DATETIME}.log
    cp ${ZFSBUILD}/root/Setup.sh ${ZFSBUILD}/home/${USERNAME}/ZFS-${MYHOSTNAME}-${SUITE}-wipe_${WIPE_FRESH}-${DATETIME}.chroot.sh

    # umount to be ready for export
    zfs umount -a

    # Back in livecd - unmount filesystems we may have missed
    # Have to escape any / in path
    ZFSBUILD_C=$(echo ${ZFSBUILD} | sed -e 's!/!\\/!'g)
    # mount | grep -v zfs | tac | awk '/\/mnt/ {print \$3}' | xargs -i{} umount -lf {}
    mount | grep -v zfs | tac | awk '/${ZFSBUILD_C}/ {print $3}' | xargs -i{} umount -lf {}
    zpool export ${POOLNAME}
else
    # For just a non-wipe new dataset, unmount and set mountpoint to / to make it bootable
    zfs umount ${POOLNAME}/ROOT/${SUITE}
    zfs set mountpoint=/ ${POOLNAME}/ROOT/${SUITE}
    zfs set org.zfsbootmenu:commandline="rw quiet root=zfs:${POOLNAME}/ROOT/${SUITE}" ${POOLNAME}/ROOT/${SUITE}
fi

