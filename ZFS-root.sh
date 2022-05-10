#!/bin/bash

# TODO: Set up EFI mirror partitions
# TODO: Finish dropbear setup
# https://hamy.io/post/0009/how-to-install-luks-encrypted-ubuntu-18.04.x-server-and-enable-remote-unlocking/#gsc.tab=0
# https://www.arminpech.de/2019/12/23/debian-unlock-luks-root-partition-remotely-by-ssh-using-dropbear/

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
# bionic/18.04 or focal/20.04.
#
# >>>>>>>>>> NOTE: This will totally overwrite the disk chosen <<<<<<<<<<<<<
#
# 1) Boot an Ubuntu live cd to get a shell. Ubuntu desktop is a good choice.
# 2) Open a shell (ctrl-t) and become root (sudo -i)
# 3) Copy this script onto the box somehow - scp from somewhere
# 4) Make it executable (chmod +x ZFS-root.sh)
# 5) Run it (./ZFS-root.sh)
#
# It will ask a few questions (username, which disk, bionic/focal etc)
# and then fully install a minimal Ubuntu system. Depending on the choices
# several partitions and zfs datasets will be created.
# 
# Part Name  Use
# ===========================================================================
#  1   GRUB  To store grub bootloader
#  2   UEFI  uefi bootloader (if chosen to activate)
#  3   BOOT  zfs pool (bpool) for /boot (bpool/BOOT/bionic) with only features
#            grub supports enabled
#  4   SWAP  Only created if HIBERNATE is enabled (may be encrypted with LUKS)
#  5   ZFS   Main zfs pool (rpool) for full system (rpool/ROOT/bionic)
# 
# Datasets created
# ================
# bpool/BOOT/bionic               Contains /boot
# bpool/BOOT/bionic@base_install  Snapshot of installed /boot
# rpool/ROOT/bionic               Contains main system
# rpool/ROOT/bionic@base_install  Snapshot of install main system
# rpool/home                      Container for user directories
# rpool/home/<username>           Dataset for initial user
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

# >>>>>>>>>> ISSUES <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# Multi-disk booting with LUKS
# One disk must be chosen to be unlocked - all the others use a derived key
# from that to unlock without extra prompts for passphrase.  Problem is that
# one disk is hard-coded in /etc/crypttab.  If THAT disk goes bad or is missing
# then unlocking fails.  Need a way to try other disks in order.

# https://github.com/saveriomiroddi/zfs-installer

# Return codes from whiptail
# 0   OK in menu
# 1   Cancel in menu
# 255 Esc key hit

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

# No magenta overrides for whiptail dialogs please
export NEWT_COLORS="none"

# Build location - will be removed prior to build
# NOTE: Can NOT have "zfs" in the name
ZFSBUILD=/mnt/builder

# Partition numbers of each partition
PARTITION_GRUB=1
PARTITION_EFI=2
PARTITION_BOOT=3
PARTITION_SWAP=4
PARTITION_DATA=5

# ZFS encryption options
ZFSENC_ROOT_OPTIONS="-o encryption=aes-256-gcm -o keylocation=prompt -o keyformat=passphrase"
# NOTE: for keyfile, put key in local /root, then later copy to target /root 
#       to be used for encrypting /home
ZFSENC_HOME_OPTIONS="-o encryption=aes-256-gcm -o keylocation=file:///root/pool.key -o keyformat=raw"

# Check for a local apt-cacher-ng system - looking for these hosts
# aptcacher.local
# bondi.local
echo "Searching for local apt-cacher-ng proxy systems ..."
PROXY=""
for CACHER in bondi.local aptcacher.local ; do
    echo -n "... testing ${CACHER}"
    CACHER=$(ping -w 2 -c 1 ${CACHER} | fgrep "bytes from" | cut -d' ' -f4)
    if [ "${CACHER}" != "" ] ; then
        echo " - found !"
        PROXY="http://${CACHER}:3142/"
        break
    else
        echo " - not found :("
    fi
done

PROXY=$(whiptail --inputbox "Enter an apt proxy. Cancel or hit <esc> for no proxy" --title "APT proxy setup" 8 70 $(echo $PROXY) 3>&1 1>&2 2>&3)
RET=${?}
(( RET )) && PROXY=
if [ ${PROXY} ]; then
    export http_proxy=${PROXY}
    export ftp_proxy=${PROXY}
    # This is for apt-get
    echo "Acquire::http::proxy \"${PROXY}\";" > /etc/apt/apt.conf.d/03proxy
fi # PROXY

apt-get -qq update
apt-get -qq --no-install-recommends --yes install software-properties-common
apt-add-repository -y universe

# Get userid and full name of main user
USERNAME=deano
UCOMMENT="Dean Carpenter"
USERINFO=$(whiptail --inputbox "Enter username (login id) and full name of user\nAs in <username> <space> <First and Last name>\n\nlogin full name here\n|---| |------------ - - -  -  -" --title "User information" 11 70 "$(echo $USERNAME $UCOMMENT)" 3>&1 1>&2 2>&3)
RET=${?}
[[ ${RET} = 1 ]] && exit 1
USERNAME=$(echo $USERINFO | cut -d' ' -f1)
UCOMMENT=$(echo $USERINFO | cut -d' ' -f2-)

# Get password, confirm and loop until confirmation OK
DONE=false
until ${DONE} ; do
    PW1=$(whiptail --passwordbox "Please enter a password for user $(echo $USERNAME)" 8 70 --title "User password" 3>&1 1>&2 2>&3)
    PW2=$(whiptail --passwordbox "Please re-enter the password to confirm" 8 70 --title "User password confirmation" 3>&1 1>&2 2>&3)
    [ "$PW1" = "$PW2" ] && DONE=true
done
UPASSWORD="$PW1"

# Hostname - cancel or blank name will exit
HOSTNAME=test
HOSTNAME=$(whiptail --inputbox "Enter hostname to be used for new system. This name may also be used for the main ZFS poolname." --title "Hostname for new system." 8 70 $(echo $HOSTNAME) 3>&1 1>&2 2>&3)
RET=${?}
(( RET )) && HOSTNAME=
if [ ! ${HOSTNAME} ]; then
    echo "Must have a hostname" 
    exit 1
fi

POOLNAME=${HOSTNAME}
POOLNAME=$(whiptail --inputbox "Enter poolname to use for main system - defaults to hostname" --title "ZFS main poolname" 8 70 $(echo $POOLNAME) 3>&1 1>&2 2>&3)
RET=${?}
(( RET )) && POOLNAME=
if [ ! ${POOLNAME} ]; then
    echo "Must have a ZFS poolname"
    exit 1
fi

BPOOLNAME=bpool
BPOOLNAME=$(whiptail --inputbox "Enter boot poolname to use for booting - defaults to bpool" --title "ZFS Boot poolname" 8 70 $(echo $BPOOLNAME) 3>&1 1>&2 2>&3)
RET=${?}
(( RET )) && BPOOLNAME=
if [ ! ${BPOOLNAME} ]; then
    echo "Must have a boot poolname"
    exit 1
fi

# Set main disk here - be sure to include the FULL path
# Get list of disks, ask user which one to install to
# Ignore cdrom etc.
readarray -t disks < <(ls -l /dev/disk/by-id | egrep -v '(CDROM|CDRW|-ROM|CDDVD|-part|md-|dm-|wwn-)' | sort -t '/' -k3 | tr -s " " | cut -d' ' -f9 | sed '/^$/d')

# If no disks available (kvm needs to use scsi, not virtio) then error out
if [ ${#disks[@]} -eq 0 ] ; then
    whiptail --title "No disks available in /dev/disk/by-id" --msgbox "No valid disk links were found in /dev/disk/by-id - ensure your target disk has a link in that directory.\n\nKVM/qemu VMs need to use the SCSI storage driver, not the default virtio one (which does not create links in /dev/disk/by-id)" 12 70
    exit 1
fi

TMPFILE=$(mktemp)
# Find longest disk name
m=-1
for disk in ${disks[@]}
do
   if [ ${#disk} -gt $m ]
   then
      m=${#disk}
   fi
done

# Set dialog box size to num disks
list_height=$(( ${#disks[@]} + 1 ))
box_height=$(( ${#disks[@]} + 8 ))
box_width=$(( ${m} + 16 ))

DONE=false
until ${DONE} ; do
    whiptail --title "List of disks" --separate-output --checklist --noitem \
        "Choose disk(s) to install to" ${box_height} ${box_width} ${list_height} \
        $( for disk in $(seq 0 $(( ${#disks[@]}-1)) ) ; do echo "${disks[${disk}]}" OFF ; done) 2> "${TMPFILE}"
    RET=${?}
    [[ ${RET} = 1 ]] && exit 1
    
    readarray -t zfsdisks < <(cat ${TMPFILE})
    if [ ${#zfsdisks[@]} != 0 ] ; then
        DONE=true
    fi
done

# multi-disk bpool (encrypted setup) will always be mirror
# Used below for creating bpool
if [ ${#zfsdisks[@]} -gt 1 ] ; then
    BPOOLRAID="mirror"
    RAIDLEVEL="mirror"
else
    BPOOLRAID=
fi

#_# DISK="/dev/disk/by-id/${DISK}"
if [ ${#zfsdisks[@]} -gt 2 ] ; then
    RAIDLEVEL=$(whiptail --title "ZPOOL raid level" --radiolist "Select ZPOOL raid level" 12 60 5 \
        single "No raid, just single disks as vdevs" OFF \
        mirror "All disks mirrored" OFF \
        raidz1 "All disks in raidz1 format" OFF \
        raidz2 "All disks in raidz2 format" OFF \
        raidz3 "All disks in raidz3 format" OFF 3>&1 1>&2 2>&3)
    RET=${?}
    [[ ${RET} = 1 ]] && exit 1
fi
# We use ${RAIDLEVEL} to set zpool raid level - just vdevs means that should be blank
if [ "${RAIDLEVEL}" = "single" ] ; then RAIDLEVEL= ; fi

DISCENC=$(whiptail --title "Select disk encryption" --radiolist "Choose which (if any) disk encryption to use" 11 60 4 \
    NOENC "No disk encryption" ON \
    ZFSENC "Enable ZFS dataset encryption" OFF \
    LUKS "Enable LUKS full disk encryption" OFF \
    3>&1 1>&2 2>&3)
RET=${?}
[[ ${RET} = 1 ]] && exit 1

# If encryption enabled, need a passphrase
if [ "${DISCENC}" != "NOENC" ] ; then
    DONE=false
    until ${DONE} ; do
        PW1=$(whiptail --passwordbox "Please enter a good long encryption passphrase" 8 70 --title "Encryption passphrase" 3>&1 1>&2 2>&3)
        PW2=$(whiptail --passwordbox "Please re-enter the encryption passphrase" 8 70 --title "Encryption passphrase confirmation" 3>&1 1>&2 2>&3)
        [ "$PW1" = "$PW2" ] && DONE=true
    done
    PASSPHRASE="$PW1"
fi

# We check /sys/power/state - if no "disk" in there, then HIBERNATE is disabled
cat /sys/power/state | fgrep disk
HIBERNATE_AVAIL=${?}

# Hibernate can only resume from a single disk, and currently not available for ZFS encryption
if [ "${DISCENC}" == "ZFSENC" ] || [ ${#zfsdisks[@]} -gt 1 ] || [ ${HIBERNATE_AVAIL} -ne 0 ] ; then
    # Set basic options for install - ZFSENC so no Hibernate available (yet)
    whiptail --title "Set options to install" --separate-output --checklist "Choose options\n\nNOTE: 18.04 HWE kernel requires pool attribute dnodesize=legacy" 18 83 7 \
        GOOGLE "Add google authenticator via pam for ssh logins" OFF \
        UEFI "Enable UEFI grub install" $( [ -d /sys/firmware/efi ] && echo ON || echo OFF ) \
        HWE "Install Hardware Enablement kernel" OFF \
        ZFS08 "Update to latest ZFS 2.1 from PPA" OFF \
        DELAY "Add delay before importing root pool - for many-disk systems" OFF \
        GNOME "Install full Ubuntu Gnome desktop" OFF \
        KDE "Install full Ubuntu KDE Plasma desktop" OFF 2>"${TMPFILE}"
else
    # Set basic options for install - ZFSENC so no Hibernate available (yet)
    whiptail --title "Set options to install" --separate-output --checklist "Choose options\n\nNOTE: 18.04 HWE kernel requires pool attribute dnodesize=legacy" 19 83 8 \
        GOOGLE "Add google authenticator via pam for ssh logins" OFF \
        UEFI "Enable UEFI grub install" $( [ -d /sys/firmware/efi ] && echo ON || echo OFF ) \
        HWE "Install Hardware Enablement kernel" OFF \
        ZFS08 "Update to latest ZFS 2.1 from PPA" OFF \
        HIBERNATE "Enable swap partition for hibernation" OFF \
        DELAY "Add delay before importing root pool - for many-disk systems" OFF \
        GNOME "Install full Ubuntu Gnome desktop" OFF \
        KDE "Install full Ubuntu KDE Plasma desktop" OFF 2>"${TMPFILE}"
fi
RET=${?}
[[ ${RET} = 1 ]] && exit 1

# Set any selected options to 'y'
while read -r TODO ; do
    eval "${TODO}"='y'
done < "${TMPFILE}"

# Any options not enabled in the basic options menu we now set to 'n'
for option in GNOME KDE UEFI HWE HIBERNATE ZFS08 DELAY GOOGLE; do
    [ ${!option} ] || eval "${option}"='n'
done

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
if [ ${GOOGLE} = "y" ] ; then
    apt-get -qq --no-install-recommends --yes install python3-qrcode libpam-google-authenticator qrencode
    # Generate a google auth config
    google-authenticator --time-based --disallow-reuse --label=${HOSTNAME} --qr-mode=UTF8 --rate-limit=3 --rate-time=30 --secret=/tmp/google_auth.txt --window-size=3 --force --quiet
    # Grab secret to build otpauth line below
    GOOGLE_SECRET=$(head -1 /tmp/google_auth.txt)

    # Have to tell whiptail library newt to use black/white text, otherwise QR code
    # is inverted and Authy can't read it
    # Set issuer to Ubuntu so we get a nice Ubuntu logo for the Authy secret
    export NEWT_COLORS='white,black'
    whiptail --title "Google Authenticator QR code and config" --msgbox "Config for ${USERNAME} is in /home/${USERNAME}/.google_authenticator\n\nBe sure to save the 5 emergency codes below\n\n$(cat /tmp/google_auth.txt)\n\nQR Code for use with OTP application (Authy etc.)\notpauth://totp/${HOSTNAME}.local:${USERNAME}?secret=${GOOGLE_SECRET}&Issuer=Ubuntu\n\n$(qrencode -m 3 -t UTF8 otpauth://totp/${HOSTNAME}.local:${USERNAME}?secret=${GOOGLE_SECRET}&issuer=Ubuntu)" 45 83
    RET=${?}
    [[ ${RET} = 1 ]] && exit 1
    export NEWT_COLORS="none"
fi

# SSH authorized keys from github for dropbear and ssh
AUTHKEYS=$(whiptail --inputbox "Dropbear and ssh need authorized ssh pubkeys to allow access to the server. Please enter any github users to pull ssh pubkeys from.  none means no keys to install\n\nDropbear is used for remote unlocking of disk encryption\n\n      ssh -p 2222 root@<ip addr>" --title "SSH pubkeys for ssh and dropbear" 13 70 $(echo none) 3>&1 1>&2 2>&3)
RET=${?}
[[ ${RET} = 1 ]] && exit 1
(( RET )) && AUTHKEYS=none

# If it's NOT a ZFS encryption setup, then clear out the ZFSENC_ROOT_OPTIONS variable
if [ "${DISCENC}" != "ZFSENC" ] ; then
    ZFSENC_ROOT_OPTIONS=""
    ZFSENC_HOME_OPTIONS=""
fi

# Swap size - if HIBERNATE enabled then this will be an actual disk partition.  
# If DISCENC == LUKS then partition will be encrypted.  If SIZE_SWAP is not
# defined here, then will be calculated to accomodate memory size (plus fudge factor).
MEMTOTAL=$(cat /proc/meminfo | fgrep MemTotal | tr -s ' ' | cut -d' ' -f2)
SIZE_SWAP=$(( (${MEMTOTAL} + 1024) / 1024 ))
SIZE_SWAP=$(whiptail --inputbox "If HIBERNATE enabled then this will be a disk partition otherwise it will be a regular ZFS dataset. If LUKS enabled then the partition will be encrypted.\nIf SWAP size not set here (left blank), then it will be calculated to accomodate memory size. Set to zero (0) to disable swap.\n\nSize of swap space in megabytes (default is calculated value)" \
    --title "SWAP size" 14 70 $(echo $SIZE_SWAP) 3>&1 1>&2 2>&3)
RET=${?}
[[ ${RET} = 1 ]] && exit 1

# Use zswap compressed page cache in front of swap ? https://wiki.archlinux.org/index.php/Zswap
# Only used for swap partition (encrypted or not)
USE_ZSWAP="\"zswap.enabled=1 zswap.compressor=lz4 zswap.max_pool_percent=25\""

# What suite is this script running under ?  bionic or focal
# Xenial does not support a couple of zfs feature flags, so have to
# not use them when creating the pools, even if the target system
# is bionic.  Pool can be upgraded after booting into the target.
SCRIPT_SUITE=$(lsb_release -cs)

# Suite to install - bionic focal
SUITE=$(whiptail --title "Select Ubuntu distribtion" --radiolist "Choose distro" 11 50 4 \
    focal "20.04 focal" ON \
    bionic "18.04 Bionic" OFF \
    3>&1 1>&2 2>&3)
RET=${?}
[[ ${RET} = 1 ]] && exit 1

#
# TODO: Make use of SUITE_EXTRAS maybe
#
case ${SUITE} in
    focal)
        SUITE_NUM="20.04"
        SUITE_EXTRAS="netplan.io expect"
        SUITE_BOOTSTRAP="wget,whois,rsync,gdisk,netplan.io"
        # Install HWE packages - set to blank or to "-hwe-20.04"
        # Gets tacked on to various packages below
        [ "${HWE}" = "y" ] && HWE="-hwe-${SUITE_NUM}" || HWE=
        # Specific zpool features available in focal
        # Depends on what suite this script is running under
        case ${SCRIPT_SUITE} in
            bionic | focal)
                SUITE_BOOT_POOL="-o feature@userobj_accounting=enabled"
                SUITE_ROOT_POOL="-O dnodesize=auto"
                ;;
            xenial)
                SUITE_BOOT_POOL=""
                SUITE_ROOT_POOL=""
                ;;
        esac
        ;;
    bionic)
        SUITE_NUM="18.04"
        SUITE_EXTRAS="netplan.io expect"
        SUITE_BOOTSTRAP="wget,whois,rsync,gdisk,netplan.io"
        # Install HWE packages - set to blank or to "-hwe-18.04"
        # Gets tacked on to various packages below
        [ "${HWE}" = "y" ] && HWE="-hwe-${SUITE_NUM}" || HWE=
        # Specific zpool features available in bionic
        # Depends on what suite this script is running under
        case ${SCRIPT_SUITE} in
            bionic | focal)
                SUITE_BOOT_POOL="-o feature@userobj_accounting=enabled"
                SUITE_ROOT_POOL="-O dnodesize=legacy"
                ;;
            xenial)
                SUITE_BOOT_POOL=""
                SUITE_ROOT_POOL=""
                ;;
        esac
        ;;
    # Default to focal 20.04
    *)
        SUITE_NUM="20.04"
        SUITE_EXTRAS="netplan.io expect"
        SUITE_BOOTSTRAP="wget,whois,rsync,gdisk,netplan.io"
        # Install HWE packages - set to blank or to "-hwe-20.04"
        # Gets tacked on to various packages below
        [ "${HWE}" = "y" ] && HWE="-hwe-${SUITE_NUM}" || HWE=
        # Specific zpool features available in focal
        # Depends on what suite this script is running under
        case ${SCRIPT_SUITE} in
            bionic | focal)
                SUITE_BOOT_POOL="-o feature@userobj_accounting=enabled"
                SUITE_ROOT_POOL="-O dnodesize=auto"
                ;;
            xenial)
                SUITE_BOOT_POOL=""
                SUITE_ROOT_POOL=""
                ;;
        esac
        ;;
esac

box_height=$(( ${#zfsdisks[@]} + 24 ))
whiptail --title "Summary of install options" --msgbox "These are the options we're about to install with :\n\n \
    Proxy $([ ${PROXY} ] && echo ${PROXY} || echo None)\n \
    $(echo $SUITE $SUITE_NUM) $([ ${HWE} ] && echo WITH || echo without) $(echo hwe kernel ${HWE})\n \
    Disk $(for disk in $(seq 0 $(( ${#zfsdisks[@]}-1)) ) ; do \
      if [ ${disk} -ne 0 ] ; then echo -n "          " ; fi ; echo ${zfsdisks[${disk}]} ; done)\n \
    Raid $([ ${RAIDLEVEL} ] && echo ${RAIDLEVEL} || echo vdevs)\n \
    Hostname $(echo $HOSTNAME)\n \
    Poolname $(echo $POOLNAME)\n \
    User $(echo $USERNAME $UCOMMENT)\n\n \
    DELAY     = $(echo $DELAY)  : Enable delay before importing zpool\n \
    ZFS ver   = $(echo $ZFS08)  : Update to latest ZFS 2.1 via PPA\n \
    GOOGLE    = $(echo $GOOGLE)  : Install google authenticator\n \
    GNOME     = $(echo $GNOME)  : Install full Ubuntu Gnome desktop\n \
    KDE       = $(echo $KDE)  : Install full Ubuntu KDE Plasma desktop\n \
    UEFI      = $(echo $UEFI)  : Enable UEFI\n \
    HIBERNATE = $(echo $HIBERNATE)  : Enable SWAP disk partition for hibernation\n \
    DISCENC   = $(echo $DISCENC)  : Enable disk encryption (No, LUKS, ZFS)\n \
    Swap size = $(echo $SIZE_SWAP)M $([ ${SIZE_SWAP} -eq 0 ] && echo ': DISABLED')\n" \
    ${box_height} 70
RET=${?}
[[ ${RET} = 1 ]] && exit 1

# Log everything we do
rm -f /root/ZFS-setup.log
exec > >(tee -a "/root/ZFS-setup.log") 2>&1
set -x

# Clear disk *before* install zfs
for disk in `seq 0 $(( ${#zfsdisks[@]} - 1))` ; do
    wipefs --all --force /dev/disk/by-id/${zfsdisks[${disk}]}
    sgdisk --zap-all /dev/disk/by-id/${zfsdisks[${disk}]}
    sgdisk --clear /dev/disk/by-id/${zfsdisks[${disk}]}
done

# Pre-OK the zfs-dkms licenses notification
cat > /tmp/selections << EOFPRE
# zfs-dkms license notification
zfs-dkms        zfs-dkms/note-incompatible-licenses  note
EOFPRE
cat /tmp/selections | debconf-set-selections

# In case ZFS is already installed in this liveCD, check versions to see
# if we need to update/upgrade
# NOTE: Chances are that the kernel module is 0.8.x and the packages are 0.7.x
#       so we may as well just upgrade to latest by PPA. Which means building
#       the newest module, which can take a while.
# Update ZFS if module mismatch, ZFS encryption selected or update-zfs selected
ZFS_INSTALLED=$(dpkg -s zfsutils-linux | fgrep Version | cut -d' ' -f2)
ZFS_MODULE=$(cat /sys/module/zfs/version)
echo "ZFS installed with ${ZFS_INSTALLED}, module with ${ZFS_MODULE}"

if [ ${ZFS_INSTALLED} != ${ZFS_MODULE} ] || [ ${DISCENC} = "ZFSENC" ] || [ ${ZFS08} = "y" ] ; then
    echo "ZFS needs an update"
    # Create an encryption key for non-root datasets (/home).  The root dataset
    # is encrypted with the passphrase above, but other datasets use a key that
    # is stored in /root/pool.key.  This key isn't available unless the root
    # dataset is unlocked, so we're still secure.
    dd if=/dev/urandom of=/root/pool.key bs=32 count=1
    apt-add-repository --yes --update ppa:jonathonf/zfs
    apt-get -qq --no-install-recommends --yes install libelf-dev zfs-dkms zfs-zed zfsutils-linux zfs-initramfs
    systemctl stop zfs-zed
    modprobe -r zfs
    modprobe zfs
    systemctl start zfs-zed
    # ensure new system uses updated ZFS
    ZFS08="y"
fi                                                                      

apt-get -qq --no-install-recommends --yes install openssh-server debootstrap gdisk zfs-initramfs

for disk in `seq 0 $(( ${#zfsdisks[@]} - 1))` ; do
    zpool labelclear -f /dev/disk/by-id/${zfsdisks[${disk}]}

    # Create new GPT partition label on disks
    sgdisk --clear /dev/disk/by-id/${zfsdisks[${disk}]}

    ## From old ZFS-setup.sh
    ## sgdisk -n1:2048:+${SIZE_EFI}M -t1:EF00 -c1:"EFI_${DISK}"  /dev/disk/by-id/${DISKS[${DISK}]}

    # Legacy (BIOS) booting
    sgdisk -a1 -n1:24K:+1000K -c1:"GRUB_${disk}" -t1:EF02 /dev/disk/by-id/${zfsdisks[${disk}]}
    
    # UEFI booting
    sgdisk     -n2:1M:+512M   -c2:"UEFI_${disk}" -t2:EF00 /dev/disk/by-id/${zfsdisks[${disk}]}
    
    # boot pool
    sgdisk     -n3:0:+1000M   -c3:"BOOT_${disk}" -t3:BF01 /dev/disk/by-id/${zfsdisks[${disk}]}
    
    #
    # TODO: figure out partitions for both ZFS and LUKS encryption
    #       both swap and main partitions
    #
    # For laptop hibernate need swap partition, encrypted or not
    if [ "${HIBERNATE}" = "y" ] ; then
        if [ ${DISCENC} != "NOENC" ] ; then
            # ZFS or LUKS Encrypted - should be partition type 8309 (Linux LUKS)
            sgdisk -n4:0:+${SIZE_SWAP}M -c4:"SWAP_${disk}" -t4:8300 /dev/disk/by-id/${zfsdisks[${disk}]}
        else
            sgdisk -n4:0:+${SIZE_SWAP}M -c4:"SWAP_${disk}" -t4:8200 /dev/disk/by-id/${zfsdisks[${disk}]}
        fi # DISCENC for ZFS or LUKS
    fi # HIBERNATE
    
    # Main data partition for root
    if [ ${DISCENC} = "LUKS" ] ; then
        # LUKS Encrypted - should be partition type 8309 (Linux LUKS)
        sgdisk -n5:0:0        -c5:"ZFS_${disk}"  -t5:8300 /dev/disk/by-id/${zfsdisks[${disk}]}
        apt-get -qq --no-install-recommends --yes install cryptsetup
    else
    # Unencrypted or ZFS encrypted
        sgdisk -n5:0:0        -c5:"ZFS_${disk}"  -t5:BF01 /dev/disk/by-id/${zfsdisks[${disk}]}
    fi # DISCENC for LUKS
done

# Have to wait a bit for the partitions to actually show up
echo "Wait for partition info to settle out"
sleep 5

# Build list of partitions to use for ...
# Boot partition (mirror across all disks)
PARTSBOOT=
PARTSSWAP=
PARTSEFI=
# ZFS partitions to create zpool with
ZPOOLDISK=
for disk in `seq 0 $(( ${#zfsdisks[@]} - 1))` ; do
    PARTSSWAP="/dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_SWAP} ${PARTSSWAP}"
    PARTSBOOT="/dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_BOOT} ${PARTSBOOT}"
    PARTSEFI="/dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_EFI} ${PARTSEFI}"
    if [ ${DISCENC} = "LUKS" ]; then
        ZPOOLDISK="/dev/mapper/root_crypt${disk} ${ZPOOLDISK}"
    else
        ZPOOLDISK="/dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_DATA} ${ZPOOLDISK}"
    fi
done

#_# ###################################
#_# Create LUKS stuff here
#_# ###################################

# Create SWAP volume for HIBERNATE, encrypted maybe
# Just using individual swap partitions - could use mdadm to mirror/raid
# them up, but meh, why ?
if [ ${HIBERNATE} = "y" ] ; then
    # Hibernate, so we need a real swap partition(s)
    for disk in `seq 0 $(( ${#zfsdisks[@]} - 1))` ; do

        case ${DISCENC} in
            LUKS)
                echo "Encrypting swap partition ${disk} size ${SIZE_SWAP}M"
                echo ${PASSPHRASE} | cryptsetup luksFormat --type luks2 -c aes-xts-plain64 -s 512 -h sha256 /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_SWAP} 
                echo ${PASSPHRASE} | cryptsetup luksOpen /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_SWAP} swap_crypt${disk}
                mkswap -f /dev/mapper/swap_crypt${disk}

                if [ ${disk} -eq 0 ] ; then
                    # Get derived key to insert into other encrypted devices
                    # To be more secure do this into a small ramdisk
                    # swap must be opened 1st to enable resume from hibernation
                    /lib/cryptsetup/scripts/decrypt_derived swap_crypt${disk} > /tmp/key
                fi
                # Add the derived key to all the other devices
                echo ${PASSPHRASE} | cryptsetup luksAddKey /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_SWAP} /tmp/key
                ;;

            ZFSENC)
                echo "ZFSENC not supported yet"
                exit 1
                ;;

            NOENC)
                # Not LUKS, so just use a regular partition
                mkswap -f /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_SWAP}
                ;;
        esac
    done
fi #HIBERNATE

# Encrypt root volume maybe
if [ ${DISCENC} = "LUKS" ] ; then
    for disk in `seq 0 $(( ${#zfsdisks[@]} - 1))` ; do
        # Encrypted LUKS root
        echo "Encrypting root ZFS ${disk}"
        echo ${PASSPHRASE} | cryptsetup luksFormat --type luks2 -c aes-xts-plain64 -s 512 -h sha256 /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_DATA} 
        echo ${PASSPHRASE} | cryptsetup luksOpen /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_DATA} root_crypt${disk}

        # If no encrypted SWAP then use 1st root device as derived key
        # otherwise assume derived key was created above in "Create SWAP volume"
        if [ ${disk} -eq 0 ] && [ ${HIBERNATE} = "n" ] ; then
            # Get derived key to insert into other encrypted devices
            # To be more secure do this into a small ramdisk
            /lib/cryptsetup/scripts/decrypt_derived root_crypt${disk} > /tmp/key
        fi

        # Add the derived key to all the other devices
        echo ${PASSPHRASE} | cryptsetup luksAddKey /dev/disk/by-id/${zfsdisks[${disk}]}-part${PARTITION_DATA} /tmp/key
    done
fi

# COMPLETELY clear out build dir
rm -rf ${ZFSBUILD}
mkdir -p ${ZFSBUILD}

# Create boot pool - only uses features supported by grub and zfs version
# https://openzfs.github.io/openzfs-docs/Getting%20Started/Ubuntu/Ubuntu%2020.04%20Root%20on%20ZFS.html
    echo "Creating boot pool ${BPOOLNAME}"
    zpool create -f -o ashift=12 -d -o autotrim=on \
      -o cachefile=/etc/zfs/zpool.cache \
      -o feature@async_destroy=enabled ${SUITE_BOOT_POOL} \
      -o feature@bookmarks=enabled \
      -o feature@embedded_data=enabled \
      -o feature@empty_bpobj=enabled \
      -o feature@enabled_txg=enabled \
      -o feature@extensible_dataset=enabled \
      -o feature@filesystem_limits=enabled \
      -o feature@hole_birth=enabled \
      -o feature@large_blocks=enabled \
      -o feature@lz4_compress=enabled \
      -o feature@spacemap_histogram=enabled \
      -O acltype=posixacl -O canmount=off -O compression=lz4 -O devices=off \
      -O normalization=formD -O relatime=on -O xattr=sa \
      -O mountpoint=/ -R ${ZFSBUILD} \
      ${BPOOLNAME} ${BPOOLRAID} ${PARTSBOOT}

# Grab the GUID of the new boot pool - will use below for zfs-import-bpool.service
# to ensure we import the right bpool (in case there are others in the system)
BPOOL_GUID=$(zpool get guid ${BPOOLNAME} -o value -H)

# Create root pool
case ${DISCENC} in
    LUKS)
        echo "Creating root pool ${POOLNAME}"
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
        zpool create -f -o ashift=12 -o autotrim=on ${SUITE_ROOT_POOL} \
          -O acltype=posixacl -O canmount=off -O compression=lz4 \
          -O atime=off \
          -O normalization=formD -O relatime=on -O xattr=sa \
          -O mountpoint=/ -R ${ZFSBUILD} \
          ${POOLNAME} ${RAIDLEVEL} ${ZPOOLDISK}
        ;;

    *)
        # Unknown option
        echo "Unknown option DISCENC = ${DISCENC}"
        exit 1
        ;;
esac

#_# # Export and re-import pool so it shows up on ${ZFSBUILD}
#_# zpool export ${POOLNAME}
#_# rm -rf ${ZFSBUILD}
#_# if [ "${LUKS}" = "y" ]; then
#_#     zpool import -d /dev/mapper -R ${ZFSBUILD} ${POOLNAME}
#_#     zpool import -d /dev/mapper -R ${ZFSBUILD} ${BPOOLNAME}
#_# else
#_#     zpool import -d /dev/disk/by-id -R ${ZFSBUILD} ${POOLNAME}
#_# fi

# If no HIBERNATE partition (not laptop, no resume etc) then just create
# a zvol for swap.  Could not create this in the block above for swap because
# the root pool didn't exist yet.
if [ ${HIBERNATE} = "n" ] && [ ${SIZE_SWAP} -ne 0 ] ; then
    # No Hibernate, so just use a zfs volume for swap
    echo "Creating swap zfs dataset size ${SIZE_SWAP}M"
    zfs create -V ${SIZE_SWAP}M -b $(getconf PAGESIZE) -o compression=zle \
      -o logbias=throughput -o sync=always \
      -o primarycache=metadata -o secondarycache=none \
      -o com.sun:auto-snapshot=false ${POOLNAME}/swap
fi #HIBERNATE

# Main filesystem datasets
UUID=$(dd if=/dev/urandom bs=1 count=100 2>/dev/null |
    tr -dc 'a-z0-9' | cut -c-6)

echo "Creating main zfs datasets"
# Container for root filesystems
if [ ${DISCENC} = "ZFSENC" ] ; then
    echo "${PASSPHRASE}" | zfs create -o canmount=off -o mountpoint=none ${ZFSENC_ROOT_OPTIONS} ${POOLNAME}/ROOT
else
    zfs create -o canmount=off -o mountpoint=none ${POOLNAME}/ROOT
fi

# Actual dataset for suite we are installing now
zfs create -o canmount=noauto -o mountpoint=/ \
    -o com.ubuntu.zsys:bootfs=yes \
    -o com.ubuntu.zsys:last-used=$(date +%s) \
    ${POOLNAME}/ROOT/${SUITE}_${UUID}

zpool set bootfs=${POOLNAME}/ROOT/${SUITE}_${UUID} ${POOLNAME}
zfs mount ${POOLNAME}/ROOT/${SUITE}_${UUID}

if [ ${DISCENC} = "ZFSENC" ] ; then
    # Making sure we have the non-root pool key used for other datasets (/home)
    mkdir ${ZFSBUILD}/root
    cp /root/pool.key ${ZFSBUILD}/root
fi

# container for boot stuff
zfs create -o canmount=off -o mountpoint=none ${BPOOLNAME}/BOOT
# Actual /boot for kernels etc
zfs create -o mountpoint=/boot ${BPOOLNAME}/BOOT/${SUITE}_${UUID}
zfs mount ${BPOOLNAME}/BOOT/${SUITE}_${UUID}
zfs create -o com.ubuntu.zsys:bootfs=no -o mountpoint=/boot/grub ${BPOOLNAME}/BOOT/grub
zfs mount ${BPOOLNAME}/BOOT/grub

# zfs create rpool/home and main user home dataset
if [ ${DISCENC} = "ZFSENC" ] ; then
    echo "${PASSPHRASE}" | zfs create -o canmount=off -o mountpoint=none -o compression=lz4 -o atime=off ${ZFSENC_HOME_OPTIONS} ${POOLNAME}/home
else
    zfs create -o canmount=off -o mountpoint=none -o compression=lz4 -o atime=off ${POOLNAME}/home
fi
zfs create -o canmount=on -o mountpoint=/home/${USERNAME} ${POOLNAME}/home/${USERNAME}

###  # Point zfs encryption to right location of keyfile for later
###  if [ ${DISCENC} = "ZFSENC" ] ; then
###      zfs set keylocation=file:///boot/pool.key ${POOLNAME}/home
###      zfs set keylocation=file:///boot/pool.key ${POOLNAME}/home/${USERNAME}
###  fi

# Show what we got before installing
echo "---------- $(tput setaf 1)About to debootstrap into ${ZFSBUILD}$(tput sgr0) -----------"
zfs list -t all
df -h
echo "---------- $(tput setaf 1)About to debootstrap into ${ZFSBUILD}$(tput sgr0) -----------"
read -t 15 QUIT

# Install basic system
echo "debootstrap to build initial system"
debootstrap --include=${SUITE_BOOTSTRAP} ${SUITE} ${ZFSBUILD}
zfs set devices=off ${POOLNAME}

# If this system will use Docker (which manages its own datasets & snapshots):
zfs create -o com.sun:auto-snapshot=false -o mountpoint=/var/lib/docker ${POOLNAME}/docker

echo ${HOSTNAME} > ${ZFSBUILD}/etc/hostname
echo "127.0.1.1  ${HOSTNAME}" >> ${ZFSBUILD}/etc/hosts

if [ ${PROXY} ]; then
    # This is for apt-get
    echo "Acquire::http::proxy \"${PROXY}\";" > ${ZFSBUILD}/etc/apt/apt.conf.d/03proxy
fi # PROXY

# Set up networking for netplan
# renderer: networkd is for text mode only, use NetworkManager for gnome
cat > ${ZFSBUILD}/etc/netplan/01_netcfg.yaml << __EOF__
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
      optional: true
__EOF__

# Google Authenticator config - put to /root to be moved to /home/${USERNAME} in setup.sh
if [ ${GOOGLE} = "y" ] ; then
    cp /tmp/google_auth.txt ${ZFSBUILD}/root
fi

# sources
cat > ${ZFSBUILD}/etc/apt/sources.list << EOF
deb http://archive.ubuntu.com/ubuntu ${SUITE} main multiverse
deb-src http://archive.ubuntu.com/ubuntu ${SUITE} main multiverse

deb http://security.ubuntu.com/ubuntu ${SUITE}-security main multiverse
deb-src http://security.ubuntu.com/ubuntu ${SUITE}-security main multiverse

deb http://archive.ubuntu.com/ubuntu ${SUITE}-updates main multiverse
deb-src http://archive.ubuntu.com/ubuntu ${SUITE}-updates main multiverse
EOF

# We put universe into its own .list file so ansible apt_repository will match 
echo "deb http://archive.ubuntu.com/ubuntu ${SUITE} universe" > ${ZFSBUILD}/etc/apt/sources.list.d/ubuntu_universe.list
echo "deb http://archive.ubuntu.com/ubuntu ${SUITE}-updates universe" >> ${ZFSBUILD}/etc/apt/sources.list.d/ubuntu_universe.list
echo "deb http://security.ubuntu.com/ubuntu ${SUITE}-security universe" >> ${ZFSBUILD}/etc/apt/sources.list.d/ubuntu_universe.list

echo "Creating Setup.sh in new system for chroot"
cat > ${ZFSBUILD}/root/Setup.sh << __EOF__
#!/bin/bash

export DELAY=${DELAY}
export SUITE=${SUITE}
export UUID=${UUID}
export POOLNAME=${POOLNAME}
export BPOOLNAME=${BPOOLNAME}
export PASSPHRASE=${PASSPHRASE}
export USERNAME=${USERNAME}
export UPASSWORD="${UPASSWORD}"
export UCOMMENT="${UCOMMENT}"
export DISCENC=${DISCENC}
export AUTHKEYS=${AUTHKEYS}
export ZFS08=${ZFS08}
export BPOOL_GUID=${BPOOL_GUID}
export GOOGLE=${GOOGLE}
export UEFI=${UEFI}
export PROXY=${PROXY}
export HWE=${HWE}
export GNOME=${GNOME}
export KDE=${KDE}
export HIBERNATE=${HIBERNATE}
export SIZE_SWAP=${SIZE_SWAP}
export PARTITION_GRUB=1
export PARTITION_EFI=2
export PARTITION_BOOT=3
export PARTITION_SWAP=4
export PARTITION_DATA=5
__EOF__

for DISK in `seq 0 $(( ${#zfsdisks[@]} - 1))` ; do
    echo "zfsdisks[${DISK}]=${zfsdisks[${DISK}]}" >> ${ZFSBUILD}/root/Setup.sh
done

cat >> ${ZFSBUILD}/root/Setup.sh << '__EOF__'
# Setup inside chroot
set -x

ln -s /proc/self/mounts /etc/mtab
apt-get -qq update

# After grub-pc installation
# grub-pc grub-pc/postrm_purge_boot_grub  boolean false
# grub-pc grub-pc/chainload_from_menu.lst boolean true
# grub-pc grub2/linux_cmdline_default     string  quiet splash
# grub-pc grub2/kfreebsd_cmdline  string
# grub-pc grub2/update_nvram      boolean true
# grub-pc grub2/linux_cmdline     string
# grub-pc grub-pc/hidden_timeout  boolean true
# grub-pc grub-pc/install_devices multiselect     /dev/disk/by-id/ata-ADATA_SP600_7D4020501003
# grub-pc grub-pc/install_devices_empty   boolean true
# grub-pc grub-pc/timeout string  0
# grub-pc grub2/unsigned_kernels  note
# grub-pc grub-pc/install_devices_failed  boolean false
# # /boot/grub/device.map has been regenerated
# grub-pc grub2/device_map_regenerated    note
# grub-pc grub-pc/kopt_extracted  boolean false
# grub-pc grub-pc/install_devices_disks_changed   multiselect
# grub-pc grub-pc/mixed_legacy_and_grub2  boolean true
# grub-pc grub2/kfreebsd_cmdline_default  string  quiet splash
# grub-pc grub2/no_efi_extra_removable    boolean false
# grub-pc grub-pc/install_devices_failed_upgrade  boolean true

# Preseed a few things
#_# Do not configure grub during package install
#_# grub-installer/bootdev                          string
#_# grub-pc         grub-pc/install_devices_empty   select true
#_# grub-pc         grub-pc/install_devices         multiselect
#_# grub-pc         grub-pc/install_devices         select
cat > /tmp/selections << EOFPRE
# zfs-dkms license notification
zfs-dkms        zfs-dkms/note-incompatible-licenses  note
# tzdata
tzdata  tzdata/Zones/US                         select Eastern
tzdata  tzdata/Zones/America                    select New_York
tzdata  tzdata/Areas                            select US
console-setup   console-setup/codeset47         select  # Latin1 and Latin5 - western Europe and Turkic languages
EOFPRE


# Set up locale - must set langlocale variable (defaults to en_US)
cat > /etc/default/locale << EOFLOCALE
LC_ALL=en_US.UTF-8
LANG=en_US.UTF-8
LANGUAGE=en_US:en
EOFLOCALE
cat /etc/default/locale >> /etc/environment
cat /tmp/selections | debconf-set-selections
locale-gen --purge "en_US.UTF-8"
# dpkg-reconfigure locales
echo "America/New_York" > /etc/timezone
ln -fs /usr/share/zoneinfo/US/Eastern /etc/localtime
dpkg-reconfigure -f noninteractive tzdata

if [ ${HIBERNATE} = "n" ] && [ ${SIZE_SWAP} -ne 0 ] ; then
    echo "Enabling swap size ${SIZE_SWAP} on /dev/zvol/${POOLNAME}/swap"
    mkswap -f /dev/zvol/${POOLNAME}/swap
fi

apt-get -qq --yes --no-install-recommends install software-properties-common debconf-utils
apt-get -qq --yes --no-install-recommends install linux-generic${HWE}

echo "-------- right after installing linux-generic -------------------------------"
ls -la /boot
echo "-----------------------------------------------------------------------------"

# If using ZFS encryption we need the jonathonf PPA for latest 2.1
if [ ${DISCENC} = "ZFSENC" ] || [ ${ZFS08} = "y" ] ; then
    apt-add-repository --yes --update ppa:jonathonf/zfs
    apt-get -qq --no-install-recommends --yes install libelf-dev zfs-dkms zfs-zed zfsutils-linux zfs-initramfs
else
    # Just install current ubuntu ZFS as-is
    apt-get -qq --yes install zfs-initramfs zfs-zed
fi

if [ "${DISCENC}" != "NOENC" ] ; then
    apt-get -qq --yes install cryptsetup dropbear-initramfs
fi

echo "-------- right after installing zfs -----------------------------------------"
ls -la /boot
echo "-----------------------------------------------------------------------------"

# Ensure cachefile exists and zfs-import-cache is active
# https://github.com/zfsonlinux/zfs/issues/8885
zpool set cachefile=/etc/zfs/zpool.cache ${POOLNAME}
systemctl enable zfs-import-cache

# Set up /etc/crypttab - ugly-ass logic here
if [ "${DISCENC}" = "LUKS" ] ; then
    # LUKS Encrypted
    if [ ${HIBERNATE} = "y" ] ; then

        # We have a LUKS encrypted swap partition, so that has to be unlocked FIRST
        # THEN we use the derived key we pull from that to unlock the other disks
        for DISK in `seq 0 $(( ${#zfsdisks[@]} - 1))` ; do
            # Set up 1st disk
            if [ ${DISK} -eq 0 ] ; then
                # Open 1st disk swap to be source of derived key
                echo "swap_crypt0 UUID=$(blkid -s UUID -o value /dev/disk/by-id/${zfsdisks[${DISK}]}-part${PARTITION_SWAP}) none luks,discard,initramfs" > /etc/crypttab
                echo "root_crypt0 UUID=$(blkid -s UUID -o value /dev/disk/by-id/${zfsdisks[${DISK}]}-part${PARTITION_DATA}) swap_crypt0 luks,discard,initramfs,keyscript=/lib/cryptsetup/scripts/decrypt_derived" >> /etc/crypttab
            else
                echo "swap_crypt${DISK} UUID=$(blkid -s UUID -o value /dev/disk/by-id/${zfsdisks[${DISK}]}-part${PARTITION_SWAP}) swap_crypt0 luks,discard,initramfs,keyscript=/lib/cryptsetup/scripts/decrypt_derived" >> /etc/crypttab
                echo "root_crypt${DISK} UUID=$(blkid -s UUID -o value /dev/disk/by-id/${zfsdisks[${DISK}]}-part${PARTITION_DATA}) swap_crypt0 luks,discard,initramfs,keyscript=/lib/cryptsetup/scripts/decrypt_derived" >> /etc/crypttab
            fi
        done

    else

        # No Hibernate, so no encrypted swap partition, so use 1st root
        # encrypted partition as source of derived key
        for DISK in `seq 0 $(( ${#zfsdisks[@]} - 1))` ; do
            # Set up 1st disk
            if [ ${DISK} -eq 0 ] ; then
                # Open 1st disk root to be source of derived key
                echo "root_crypt0 UUID=$(blkid -s UUID -o value /dev/disk/by-id/${zfsdisks[${DISK}]}-part${PARTITION_DATA}) none luks,discard,initramfs" > /etc/crypttab
            else
                echo "root_crypt${DISK} UUID=$(blkid -s UUID -o value /dev/disk/by-id/${zfsdisks[${DISK}]}-part${PARTITION_DATA}) root_crypt0 luks,discard,initramfs,keyscript=/lib/cryptsetup/scripts/decrypt_derived" >> /etc/crypttab
            fi
        done

    fi # HIBERNATE
fi # DISCENC for LUKS crypttab


# # Create grub device.map for just install drives - eg.
# # grub-mkdevicemap -nvv
# # (hd0)   /dev/disk/by-id/ata-VBOX_HARDDISK_VB7e33e873-e3c9fd91
# # (hd1)   /dev/disk/by-id/ata-VBOX_HARDDISK_VB3f3328bd-1d7db667
# # (hd2)   /dev/disk/by-id/ata-VBOX_HARDDISK_VB11f330ab-76c3340a
# #
# # We do this manually rather than grub-mkdevicemap to ensure we only use the disks
# # listed in ZFS-setup.disks.txt, in case there are other disks in the system
# echo "" > /boot/grub/device.map
# for DISK in `seq 0 $(( ${#zfsdisks[@]} - 1))` ; do
#   echo "(hd${DISK}) /dev/disk/by-id/${zfsdisks[${DISK}]}" >> /boot/grub/device.map
# done
# echo "------------------ device.map ------------------------------"
# cat /boot/grub/device.map
# echo "------------------ device.map ------------------------------"

# Set up which disks to install grub to
echo -n "grub-pc  grub-pc/install_devices  multiselect  " >> /tmp/selections
for disk in `seq 0 $(( ${#zfsdisks[@]} - 1))` ; do
    echo -n "  /dev/disk/by-id/${zfsdisks[$disk]}," >> /tmp/selections
done
echo " " >> /tmp/selections
cat /tmp/selections | debconf-set-selections

# Copy default grub config (normally installed with grub-pc, but not with grub-pc-bin
# So need to install grub2-common here to get it
# Also installed by grub-efi-amd64-signed below if UEFI is selected
apt-get -qq --yes install grub2-common
cp -f /usr/share/grub/default/grub /etc/default/grub

echo "-------- right after installing grub ----------------------------------------"
ls -la /boot
echo "-----------------------------------------------------------------------------"

#_#
#_# TODO: loop through disks to use multiple partitions
#_#
# Using a swap partition ?
if [ ${HIBERNATE} = "y" ] ; then

    # Hibernate is enabled - we HAVE to use a swap partition
    # Also, only works with a single disk (as in laptop)
    if [ "${DISCENC}" = "LUKS" ] ; then

        # LUKS encrypted
        sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT.*/GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash bootdegraded=true resume=\/dev\/mapper\/swap_crypt0 ${USE_ZSWAP}\"/" /etc/default/grub
        echo "/dev/mapper/swap_crypt0 none swap discard,sw 0 0" >> /etc/fstab
        echo "RESUME=/dev/mapper/swap_crypt0" > /etc/initramfs-tools/conf.d/resume

    else

        # Not LUKS encrypted
        sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT.*/GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash bootdegraded=true resume=UUID=$(blkid -s UUID -o value ${DISK}-part${PARTITION_SWAP}) ${USE_ZSWAP}\"/" /etc/default/grub
        echo "UUID=$(blkid -s UUID -o value ${DISK}-part${PARTITION_SWAP}) none swap discard,sw 0 0" >> /etc/fstab
        echo "RESUME=UUID=$(blkid -s UUID -o value ${DISK}-part${PARTITION_SWAP})" > /etc/initramfs-tools/conf.d/resume

    fi # DISCENC for LUKS

    # If using zswap enable lz4 compresstion
    if [ "ZZ${USE_ZSWAP}" != "ZZ" ]; then
        echo "lz4" >> /etc/modules
        echo "lz4" >> /etc/initramfs-tools/modules
    fi

else
    # No swap partition
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash bootdegraded=true"/' /etc/default/grub
    if [ ${SIZE_SWAP} -ne 0 ] ; then
        echo "/dev/zvol/${POOLNAME}/swap none swap discard,sw 0 0" >> /etc/fstab
    fi
    echo "RESUME=none" > /etc/initramfs-tools/conf.d/resume
fi # HIBERNATE


#_#
#_# TODO: Setup debconf selections to NOT install to disks, use grub-install
#_#       in loop for each disks.  Install grub-pc-bin instead of grub-pc ?
#_#
# Grub for legacy BIOS
debconf-get-selections > /root/grub-pc-pre-install.txt
apt-get -qq --yes install grub-pc-bin
debconf-get-selections > /root/grub-pc-post-install.txt

echo "-------- right after installing grub-pc-bin ---------------------------------"
ls -la /boot
echo "-----------------------------------------------------------------------------"


#_#
#_# TODO: Create mdadm mirror for EFI partitions
#_#
# Install grub
if [ "${UEFI}" = "y" ] ; then
    # Grub for UEFI
    #
    # Possibly use this in debconf selections
    # https://askubuntu.com/questions/955583/preseeding-ubuntu-16-04-for-a-hyper-v-vm-fails-to-install-the-uefi-boot-section
    # grub-installer/force-efi-extra-removable boolean true
    #
    apt-get -qq --yes install dosfstools

    for DISK in `seq 0 $(( ${#zfsdisks[@]} - 1))` ; do
        mkdosfs -F 32 -s 1 -n EFI /dev/disk/by-id/${zfsdisks[${DISK}]}-part${PARTITION_EFI}
        mkdir /boot/efi
        echo "# Ensure that /boot is mounted via zfs before trying to mount /boot/efi" >> /etc/fstab
        echo PARTUUID=$(blkid -s PARTUUID -o value \
              /dev/disk/by-id/${zfsdisks[${DISK}]}-part${PARTITION_EFI}) \
              /boot/efi vfat nofail,x-systemd.device-timeout=1,x-systemd.after=zfs-mount.service 0 1 >> /etc/fstab
    done
    mount /boot/efi

#_#
#_# TODO: Setup debconf selections to NOT install to disks, use grub-install
#_#       in loop for each disks
#_# NOTE: grub-install is further down in script - move here ?
#_#
    debconf-get-selections > /root/grub-efi-pre-install.txt
    apt-get -qq install --yes grub-efi-amd64-signed shim-signed
    debconf-get-selections > /root/grub-efi-post-install.txt
fi # UEFI


# Ensure grub supports ZFS and reset timeouts to 5s
sed -i "s/GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"net.ifnames=0 biosdevname=0 rootdelay=9 root=ZFS=${POOLNAME}\/ROOT\/${SUITE}_${UUID}\"/" /etc/default/grub
sed -i 's/GRUB_TIMEOUT_STYLE=hidden/# GRUB_TIMEOUT_STYLE=hidden/' /etc/default/grub
sed -i 's/GRUB_TIMEOUT=0/GRUB_TIMEOUT=5/' /etc/default/grub
cat >> /etc/default/grub << EOF

# Ensure both timeouts are 5s
GRUB_RECOVERFAIL_TIMEOUT=5
GRUB_RECORDFAIL_TIMEOUT=5

GRUB_GFXPAYLOAD_LINUX="keep"
GRUB_GFXMODE="800x600x32"
GRUB_TERMINAL=console

# Sometimes os_prober fails with device busy. Only really needed for multi-OS
GRUB_DISABLE_OS_PROBER=true
EOF


#_#
#_# Install grub to each disk in list
#_#
echo "-------- installing grub to each disk ---------------------------------------"
for DISK in `seq 0 $(( ${#zfsdisks[@]} - 1))` ; do
    # Install bootloader grub for either UEFI or legacy bios
    if [ "${UEFI}" = "y" ] ; then
        grub-install --target=x86_64-efi --efi-directory=/boot/efi \
          --bootloader-id=ubuntu --recheck --no-floppy /dev/disk/by-id/${zfsdisks[${DISK}]}
        umount /boot/efi
    fi # UEFI
    grub-install --target=i386-pc /dev/disk/by-id/${zfsdisks[${DISK}]}
done


# Grub installation
# Verify ZFS boot is seen
echo "${DASHES}"
echo "Please verify that ZFS shows up below for grub-probe"
grub-probe /boot
read -t 5 QUIT

#_#
#_# Potentially add delay before importing root pool in initramfs
#_#
if [ ${DELAY} = "y" ] ; then
    echo "${DASHES}"
    echo "On systems with lots of disks, enumerating them can sometimes take a long"
    echo "time, which means the root disk(s) may not have been enumerated before"
    echo "ZFS tries to import the root pool. That drops you to an initramfs prompt"
    echo "where you have to 'zfs import -N <root_pool> ; exit'"
    echo "So we set a delay in the initramfs to wait 25s before importing"
    echo "In /etc/default/zfs set ZFS_INITRD_POST_MODPROBE_SLEEP=10"
    echo "In /etc/default/zfs set ZFS_INITRD_PRE_MOUNTROOT_SLEEP=10"
    # First ensure the lines are there ... then ensure they have the right value
    grep -qxF 'ZFS_INITRD_POST_MODPROBE_SLEEP' /etc/default/zfs || echo "ZFS_INITRD_POST_MODPROBE_SLEEP='10'" >> /etc/default/zfs
    grep -qxF 'ZFS_INITRD_PRE_MOUNTROOT_SLEEP' /etc/default/zfs || echo "ZFS_INITRD_PRE_MOUNTROOT_SLEEP='10'" >> /etc/default/zfs
    sed -i "s/ZFS_INITRD_POST_MODPROBE_SLEEP=.*/ZFS_INITRD_POST_MODPROBE_SLEEP='10'/" /etc/default/zfs
    sed -i "s/ZFS_INITRD_PRE_MOUNTROOT_SLEEP=.*/ZFS_INITRD_PRE_MOUNTROOT_SLEEP='10'10/" /etc/default/zfs
fi


#------------------- Dropbear stuff between dashed lines ----------------------------------------------------------------------
# Only if encrypted disk, LUKS or ZFSENC
# Want to embed the IP address(es) of the server into the decrypt prompt
# ip a | fgrep "inet " | fgrep -v "host lo" | awk '{ print $2 }' | xargs
# awk '/32 host/ { print f } {f=$2}' /proc/net/fib_trie | sort | uniq | grep -v 127.0.0.1

if [ ${DISCENC} != "NOENC" ] ; then

    apt-get -qq --no-install-recommends --yes install busybox dropbear-initramfs

    if [ "$(cat /proc/cpuinfo | fgrep aes)" != "" ] ; then
        echo "aesni-intel" >> /etc/modules
        echo "aesni-intel" >> /etc/initramfs-tools/modules
    fi
    echo "aes-x86_64" >> /etc/modules
    echo "aes-x86_64" >> /etc/initramfs-tools/modules

    # Set up dropbear defaults
    sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
    sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=2222/g' /etc/default/dropbear 
    sed -i '/BUSYBOX=auto/c\BUSYBOX=y' /etc/initramfs-tools/initramfs.conf 

    # Add current IP address to "Please unlock" boot message
    # Have to escapt $ and `
    sed -i "s^Please unlock disk \$CRYPTTAB_NAME^Please unlock disk \$CRYPTTAB_NAME at \`awk '/32 host/ { print f } {f=\$2}' /proc/net/fib_trie | sort | uniq | grep -v 127.0.0.1\` ^" /usr/lib/cryptset
up/functions

    # NOTE: We *could* add the option "-c unlock" to automagically run the
    #       unlock command here.  But doing it via /root/.profile below
    #       allows us to drop to a shell if necessary.
    m_value='DROPBEAR_OPTIONS="-p 2222 -s -j -k -I 60"' 
    sed -i "s/.DROPBEAR_OPTIONS./${m_value}/g" /etc/dropbear-initramfs/config

    # Convert dropbear keys
    /usr/lib/dropbear/dropbearconvert dropbear openssh /etc/dropbear-initramfs/dropbear_rsa_host_key /etc/dropbear-initramfs/id_rsa
    dropbearkey -y -f /etc/dropbear-initramfs/dropbear_rsa_host_key |grep "^ssh-rsa " > /etc/dropbear-initramfs/id_rsa.pub

    # Set up dropbear authorized_keys
    touch /etc/dropbear-initramfs/authorized_keys
    if [ "${AUTHKEYS}" != "none" ] ; then
        for SSHKEY in ${AUTHKEYS} ; do
            FETCHKEY=$(wget --quiet -O- https://github.com/${SSHKEY}.keys)
            if [ ${#FETCHKEY} -ne 0 ] ; then
                echo "####### Github ${SSHKEY} keys #######" >> /etc/dropbear-initramfs/authorized_keys
                echo "no-port-forwarding,no-agent-forwarding,no-x11-forwarding ${FETCHKEY}" >> /etc/dropbear-initramfs/authorized_keys
                echo "#" >> /etc/dropbear-initramfs/authorized_keys
            fi
        done
    fi

    # Create crypt_unlock.sh script
    # Lots of ugly \ and \\\ in place.  Single \ is to NOT dereference the
    # variable in the crypt_unlock.sh script - that is, we want the name of
    # the variable there, not the value.  Triple \\\ is inception - one level
    # deeper.  crypt_unlock.sh ALSO creates a few scripts, and the triple \\\
    # means to NOT dereference the variable or back-tick - pass them directly
    # into the created scripts
    cat > /usr/share/initramfs-tools/hooks/crypt_unlock.sh << EOFD
#!/bin/sh
# /usr/share/initramfs-tools/hooks/crypt_unlock.sh

PREREQ="dropbear"

prereqs() {
  echo "\$PREREQ"
}

case "\$1" in
  prereqs)
    prereqs
    exit 0
  ;;
esac

. "\${CONFDIR}/initramfs.conf" 
. /usr/share/initramfs-tools/hook-functions

# if [ "\${DROPBEAR}" != "n" ] && [ -r "/etc/zfs" ] ; then
if [ "\${DROPBEAR}" != "n" ] ; then

    # Automagicallly run the unlock command via /root/.profile
    # If preferred, could dispense with this and add "-c unlock"
    # to the DROPBEAR_OPTIONS var in /etc/dropbear-initramfs/config
    # But then no option to drop to a shell
    # NOTE: 1st char here is a TAB, because <<- strips only leading TABS
    #       from the HereDoc.  Spaces are left alone.  Makes for nice indentation
    ROOTDIR=\`ls -1d \${DESTDIR}/root* | tail -1\`
    cat > "\${ROOTDIR}/.profile" <<- EOF
	ctrl_c_exit() {
	  exit 1
	}
	ctrl_c_shell() {
	  # Ctrl-C during .profile appears to mangle terminal settings
	  reset
	}

	echo "Unlocking rootfs... Type Ctrl-C for a shell."
	trap ctrl_c_shell INT

	unlock && exit 1 || echo "Run unlock to try unlocking again"
	trap INT
	EOF

    # NOTE: 1st char here is a TAB, because <<- strips only leading TABS
    #       from the HereDoc.  Spaces are left alone.  Makes for nice indentation
    cat > "\${DESTDIR}/bin/unlock" <<- EOF 
	#!/bin/sh 
	if [ ${DISCENC} == ZFSENC ] ; then
	    if PATH=/lib/unlock:/bin:/sbin /scripts/local-top/cryptroot; then 
	        /sbin/zfs load-key ${POOLNAME}/ROOT

	        # Get root dataset
	        DROP_ROOT=\\\`/sbin/zfs get com.ubuntu.zsys:bootfs | grep yes | grep -v "@" | cut -d" " -f1\\\`
	        mount -o zfsutil -t zfs \\\${DROP_ROOT} /
	        if [ \\\$? == 0 ]; then 
	            echo OK - ZFS Root Pool Decrypted
	            kill \\\`ps | grep [z]fs | awk '{print \\\$1}'\\\` 2>/dev/null
	            kill \\\`ps | grep [p]lymouth | awk '{print \\\$1}'\\\` 2>/dev/null
	            kill -9 \\\`ps | grep [-]sh | awk '{print \\\$1}'\\\` 2>/dev/null
	            exit 0 
	        fi
	    fi
	fi

	if [ ${DISCENC} == LUKS ] ; then
	    cryptroot-unlock
	    if [ \\\$? == 0 ]; then 
	        echo OK - LUKS root disk Decrypted
	        kill \\\`ps | grep [z]fs | awk '{print \\\$1}'\\\` 2>/dev/null
	        kill \\\`ps | grep [p]lymouth | awk '{print \\\$1}'\\\` 2>/dev/null
	        kill -9 \\\`ps | grep [-]sh | awk '{print \\\$1}'\\\` 2>/dev/null
	        exit 0 
	    fi
	fi

	exit 1 
	EOF

    chmod 755 "\${DESTDIR}/bin/unlock"
    mkdir -p "\${DESTDIR}/lib/unlock"

    # NOTE: 1st char here is a TAB, because <<- strips only leading TABS
    #       from the HereDoc.  Spaces are left alone.  Makes for nice indentation
    cat > "\${DESTDIR}/lib/unlock/plymouth" <<- EOF 
	#!/bin/sh
	[ "\\\$1" == "--ping" ] && exit 1
	/bin/plymouth "\\\$@" 
	EOF

    chmod 755 "\${DESTDIR}/lib/unlock/plymouth"
    echo To unlock root-partition run "unlock" >> \${DESTDIR}/etc/motd
fi # DROPBEAR != n
EOFD

chmod +x /usr/share/initramfs-tools/hooks/crypt_unlock.sh

# Disable dropbear on main server
systemctl disable dropbear

fi # DISCENC != NOENC
#------------------- Dropbear stuff between dashed lines ----------------------------------------------------------------------


###  No need to update yet
###
###  echo "--------- about to update initrd and grub -----------------------------------"
###  ls -la /boot
###  echo "-----------------------------------------------------------------------------"
###  
###  # Update initrd
###  update-initramfs -c -k all
###  
###  # Update boot config
###  update-grub


echo "-------- installing basic packages ------------------------------------------"
#_#
#_# Install basic packages
#_#
apt-get -qq --no-install-recommends --yes install expect most vim-nox rsync whois gdisk \
    openssh-server avahi-daemon libnss-mdns

#_#
#_# Copy Avahi SSH service file into place
#_#
cp /usr/share/doc/avahi-daemon/examples/ssh.service /etc/avahi/services

# For ZFSENC we need to set up a script and systemd unit to load the keyfile
if [ ${DISCENC} = "ZFSENC" ] ; then
  cat > /usr/local/bin/zfs-multi-mount.sh << 'EOF'
#!/usr/bin/env bash

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
  if [ $key != "prompt" ] ; then
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
  chmod 755 /usr/local/bin/zfs-multi-mount.sh

  cat > /etc/systemd/system/zfs-load-key.service << 'EOF'
[Unit]
Description=Import keys for all datasets
DefaultDependencies=no
Before=zfs-mount.service
Before=systemd-user-sessions.service
After=zfs-import.target
OnFailure=emergency.target

[Service]
Type=oneshot
RemainAfterExit=yes

ExecStart=zfs-multi-mount.sh --systemd --no-mount

[Install]
WantedBy=zfs-mount.service
EOF
  systemctl enable zfs-load-key.service

fi # if ZFSENC

####    #------------------- Dropbear stuff between dashed lines ----------------------------------------------------------------------
####    # Only if encrypted disk, LUKS or ZFSENC
####    if [ ${DISCENC} != "NOENC" ] ; then
####    
####    	if [ "`cat /proc/cpuinfo | fgrep aes`" != "" ] ; then
####    		echo "aesni-intel" >> /etc/modules
####    		echo "aesni-intel" >> /etc/initramfs-tools/modules
####    	fi
####    	echo "aes-x86_64" >> /etc/modules
####    	echo "aes-x86_64" >> /etc/initramfs-tools/modules
####    
####    #   ===========================================================================
####    	# Reduce cryptroot timeout from 180s to 30s and remove dropping to shell if missing device
####    	# Include system IP address on boot unlock screen
####    	sed -i "
####            s/slumber=180/slumber=30/g
####            s/panic/break # panic/
####    		s/Please unlock disk/For \$eth0IP Please unlock disk/
####    		/PREREQ=/ {
####    		a \
####    # Need to pause here to let network come up\n\
####    sleep 7\n\
####    eth0IP=\$(/sbin/ip -4 addr show eth0 | /bin/sed -n '/inet /s/.*inet \([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/p')
####    		
####    		}
####    	" /usr/share/initramfs-tools/scripts/local-top/cryptroot
####    	
####    #   ===========================================================================
####        # Install dropbear for ssh access into initramfs to unlock disk(s)
####        # NOTE: openssh-server must be installed first (done above)
####    	apt-get -qq -y install dropbear
####    	cat > /etc/initramfs-tools/conf.d/dropbear_network << '__EOFF__'
####    DROPBEAR=y
####    CRYPTSETUP=y
####    __EOFF__
####    
####    #   ===========================================================================
####        ##### Need the full version of busybox if we use it
####    	cat > /etc/initramfs-tools/hooks/busybox2 << '__EOFF__'
####    #!/bin/sh
####    ##### Need the full version of busybox if we use it
####    
####    PREREQ=""
####    
####    prereqs() {
####            echo "$PREREQ"
####    }
####    
####    case $1 in
####    # get pre-requisites
####    prereqs)
####            prereqs
####            exit 0
####            ;;
####    esac
####    
####    # busybox
####    if [ "${BUSYBOX}" != "n" ] && [ -e /bin/busybox ]; then
####    	. /usr/share/initramfs-tools/hook-functions
####    	rm -f ${DESTDIR}/bin/busybox
####    	copy_exec /bin/busybox /bin
####    	copy_exec /usr/bin/xargs /bin
####    fi
####    __EOFF__
####    	chmod +x /etc/initramfs-tools/hooks/busybox2
####    
####    #   ===========================================================================
####        ##### Unlock script for dropbear in initramfs
####    	cat > /etc/initramfs-tools/hooks/mount_cryptroot << '__EOFF__'
####    #!/bin/sh
####    
####    # This script generates two scripts in the initramfs output,
####    # /root/mount_cryptroot.sh and /root/.profile
####    # https://projectgus.com/2013/05/encrypted-rootfs-over-ssh-with-debian-wheezy/
####    
####    ALLOW_SHELL=1
####    # Set this to 1 before running update-initramfs if you want
####    # to allow authorized users to type Ctrl-C to drop to a
####    # root shell (useful for debugging, potential for abuse.)
####    #
####    # (Note that even with ALLOW_SHELL=0 it may still be possible
####    # to achieve a root shell.)
####    
####    PREREQ="dropbear"
####    prereqs() {
####        echo "$PREREQ"
####    }
####    case "$1" in
####        prereqs)
####            prereqs
####            exit 0
####        ;;
####    esac
####    
####    . "${CONFDIR}/initramfs.conf"
####    . /usr/share/initramfs-tools/hook-functions
####    
####    if [ -z ${DESTDIR} ]; then
####        exit
####    fi
####    
####    # 16.04/xenial uses a tempdir for /root homedir, so need to find which one it is
####    # something like /root-2EpTFt/
####    ROOTDIR=`ls -1d ${DESTDIR}/root* | tail -1`
####    SCRIPT="${ROOTDIR}/mount_cryptroot.sh"
####    cat > "${SCRIPT}" << 'EOF'
####    #!/bin/sh
####    CMD=
####    while [ -z "$CMD" -o -z "`pidof askpass plymouth`" ]; do
####      # force use of busybox for ps
####      CMD=`busybox ps -o args | grep cryptsetup | grep -i open | grep -v grep`
####      # Not using busybox, using klibc
####      # CMD=`ps -o args | grep cryptsetup | grep -i open | grep -v grep`
####    
####      sleep 0.1
####    done
####    while [ -n "`pidof askpass plymouth`" ]; do
####      $CMD && kill -9 `pidof askpass plymouth` && echo "Success"
####    done
####    EOF
####    
####    chmod +x "${SCRIPT}"
####    
####    # Run mount_cryptroot by default and close the login session afterwards
####    # If ALLOW_SHELL is set to 1, you can press Ctrl-C to get to an interactive prompt
####    cat > "${ROOTDIR}/.profile" << EOF
####    ctrl_c_exit() {
####      exit 1
####    }
####    ctrl_c_shell() {
####      # Ctrl-C during .profile appears to mangle terminal settings
####      reset
####    }
####    if [ "$ALLOW_SHELL" == "1" ]; then
####      echo "Unlocking rootfs... Type Ctrl-C for a shell."
####      trap ctrl_c_shell INT
####    else
####      echo "Unlocking rootfs..."
####      trap ctrl_c_exit INT
####    fi
####    ${ROOTDIR#$DESTDIR}/mount_cryptroot.sh && exit 1 || echo "Run ./mount_cryptroot.sh to try unlocking again"
####    trap INT
####    EOF
####    __EOFF__
####    	chmod +x /etc/initramfs-tools/hooks/mount_cryptroot
####      
####    #   ===========================================================================
####    	##### Second script to handle converting host SSH keys.
####    	# You might NOT want to use this as now your SSH keys are stored inside
####    	# plaintext initramfs instead of only encypted volume.
####        # NOTE: Need to escape $ because we need ${USERNAME}
####    	cat > /etc/initramfs-tools/hooks/dropbear.fixup2 << __EOFF__
####    #!/bin/sh
####    PREREQ="dropbear"
####    prereqs() {
####        echo "\$PREREQ"
####    }
####    case "\$1" in
####        prereqs)
####            prereqs
####            exit 0
####        ;;
####    esac
####        
####    . "\${CONFDIR}/initramfs.conf"
####    . /usr/share/initramfs-tools/hook-functions
####        
####    if [ "\${DROPBEAR}" != "n" ] && [ -r "/etc/crypttab" ] ; then
####        # Convert SSH keys
####    	echo "----- Installing host SSH keys into dropbear initramfs -----"
####    	/usr/lib/dropbear/dropbearconvert openssh dropbear /etc/ssh/ssh_host_rsa_key \${DESTDIR}/etc/dropbear/dropbear_rsa_host_key
####    	/usr/lib/dropbear/dropbearconvert openssh dropbear /etc/ssh/ssh_host_ecdsa_key \${DESTDIR}/etc/dropbear/dropbear_ecdsa_host_key
####    
####        # Copy main user authorized_keys for dropbear
####        # This way main user can ssh into rebooted box to enter decryption key
####    	[ ! -e /etc/initramfs-tools/root/.ssh ] && mkdir -p /etc/initramfs-tools/root/.ssh
####        [ -e /home/${USERNAME}/.ssh/authorized_keys ] && cp -f /home/${USERNAME}/.ssh/authorized_keys /etc/initramfs-tools/root/.ssh
####    fi
####    __EOFF__
####     
####    # Make it executable
####    chmod a+x /etc/initramfs-tools/hooks/dropbear.fixup2
####      
####    fi
####    #------------------- Dropbear stuff between dashed lines ----------------------------------------------------------------------


# ===========================================================================
# Enable importing bpool
cat >> /etc/systemd/system/zfs-import-bpool.service << EOF
# We use the specific GUID of the bpool ${BPOOLNAME} (${BPOOL_GUID}) to ensure
# we import the correct bpool (in case there are others on this system)

[Unit]
DefaultDependencies=no
Before=zfs-import-scan.service
Before=zfs-import-cache.service

[Service]
Type=oneshot
RemainAfterExit=yes

# Importing pool with cachefile=none results in on-disk /etc/zfs/zpool.cache
# being overwritten with ZERO imports. So NO pools in cachefile to import.
# This just moves zpool.cache aside, imports bpool, puts cache back in place
# See last comment in https://github.com/openzfs/zfs/issues/8549

ExecStartPre=/bin/sh -c '[ -f /etc/zfs/zpool.cache ] && mv /etc/zfs/zpool.cache /etc/zfs/preboot_zpool.cache || true'
# Import bpool with guid ${BPOOL_GUID}
ExecStart=/sbin/zpool import -N -o cachefile=none ${BPOOL_GUID} ${BPOOLNAME}
ExecStartPost=/bin/sh -c '[ -f /etc/zfs/preboot_zpool.cache ] && mv /etc/zfs/preboot_zpool.cache /etc/zfs/zpool.cache || true'

# Need a delay to allow disks to settle to import other pools via zfs-import-cache
ExecStartPost=/bin/sleep 15

[Install]
WantedBy=zfs-import.target
EOF
systemctl enable zfs-import-bpool.service

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
cat >> /etc/bash.bashrc << EOF

PS1="${debian_chroot:+($debian_chroot)}\[\$(tput setaf 2)\]\u@\[\$(tput bold)\]\[\$(tput setaf 5)\]\h\[\$(tput sgr0)\]\[\$(tput setaf 7)\]:\[\$(tput bold)\]\[\$(tput setaf 4)\]\w\[\$(tput setaf 7)\]\\$ \[\$(tput sgr0)\]"

# https://unix.stackexchange.com/questions/99325/automatically-save-bash-command-history-in-screen-session
PROMPT_COMMAND="history -a; history -c; history -r; \${PROMPT_COMMAND}"
EOF

cat >> /etc/skel/.bashrc << EOF

PS1="${debian_chroot:+($debian_chroot)}\[\$(tput setaf 2)\]\u@\[\$(tput bold)\]\[\$(tput setaf 5)\]\h\[\$(tput sgr0)\]\[\$(tput setaf 7)\]:\[\$(tput bold)\]\[\$(tput setaf 4)\]\w\[\$(tput setaf 7)\]\\$ \[\$(tput sgr0)\]"

# https://unix.stackexchange.com/questions/99325/automatically-save-bash-command-history-in-screen-session
PROMPT_COMMAND="history -a; history -c; history -r; \${PROMPT_COMMAND}"
EOF

cat >> /etc/skel/.bash_aliases << EOF
alias ls='ls --color=auto'
alias l='ls -la'
alias lt='ls -lat | head -25'
EOF

cat >> /root/.bashrc << "EOF"
# PS1='\[\033[01;37m\]\[\033[01;41m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]$ '
PS1='\[\033[01;37m\]\[\033[01;41m\]\u@\[\033[00m\]\[$(tput bold)\]\[$(tput setaf 5)\]\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]$ '

# https://unix.stackexchange.com/questions/99325/automatically-save-bash-command-history-in-screen-session
PROMPT_COMMAND="history -a; history -c; history -r; ${PROMPT_COMMAND}"
HISTSIZE=5000
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LANGUAGE=en_US.UTF-8
EOF

cat >> /root/.bash_aliases << EOF
alias ls='ls --color=auto'
alias l='ls -la'
alias lt='ls -lat | head -25'
EOF


# Create user
useradd -c "${UCOMMENT}" -p $(echo "${UPASSWORD}" | mkpasswd -m sha-512 --stdin) -M --home-dir /home/${USERNAME} --user-group --groups adm,cdrom,dip,lpadmin,plugdev,sambashare,sudo --shell /bin/bash ${USERNAME}
# Since /etc/skel/* files aren't copied, have to do it manually
rsync -a /etc/skel/ /home/${USERNAME}
mkdir /home/${USERNAME}/.ssh
chmod 700 /home/${USERNAME}/.ssh

if [ "${AUTHKEYS}" != "none" ] ; then
  for SSHKEY in ${AUTHKEYS} ; do
      FETCHKEY=$(wget --quiet -O- https://github.com/${SSHKEY}.keys)
      if [ ${#FETCHKEY} -ne 0 ] ; then
          echo "####### Github ${SSHKEY} keys #######" >> /home/${USERNAME}/.ssh/authorized_keys 
          echo "${FETCHKEY}" >> /home/${USERNAME}/.ssh/authorized_keys 
          echo "#" >> /home/${USERNAME}/.ssh/authorized_keys
      fi
  done
fi

chown -R ${USERNAME}.${USERNAME} /home/${USERNAME}

# Allow read-only zfs commands with no sudo password
cat /etc/sudoers.d/zfs | sed -e 's/#//' > /etc/sudoers.d/zfsALLOW

# Install main ubuntu gnome desktop, plus maybe HWE packages
if [ "${GNOME}" = "y" ] ; then
    # NOTE: 18.04 has an xserver-xorg-hwe-18.04 package, 20.04 does NOT
    case ${SUITE} in 
        focal)
            apt-get -qq --yes install ubuntu-desktop
            ;;
        bionic)
            apt-get -qq --yes install ubuntu-desktop xserver-xorg${HWE}
            ;;
        *)
            # Default to not specifying hwe xorg just in case
            apt-get -qq --yes install ubuntu-desktop
            ;;
    esac
fi # GNOME

# Install main ubuntu kde desktop
if [ "${KDE}" = "y" ] ; then
    apt-get -qq --yes install kde-full
fi # KDE
    
if [ "${GNOME}" = "y" ] || [ "${KDE}" = "y" ] ; then
    # Ensure networking is handled by NetworkManager
    # NOTE: Using <<-EOF so it wills strip leading TAB chars
    #       MUST be TAB chars, not spaces
    cat > /etc/netplan/01_netcfg.yaml <<-EOF
	network:
	  version: 2
	  renderer: NetworkManager
	EOF
    cat > /etc/NetworkManager/conf.d/10-globally-managed-devices.conf <<-EOF
	[keyfile]
	unmanaged-devices=*,except:type:wifi,except:type:wwan,except:type:ethernet
	EOF
    
    # Enable hibernate in upower and logind if desktop is installed
    if [ -d /etc/polkit-1/localauthority/50-local.d ] ; then
        cat > /etc/polkit-1/localauthority/50-local.d/com.ubuntu.enable-hibernate.pkla <<-EOF
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
fi # GNOME KDE

# Configure google authenticator if we have a config
if [ "${GOOGLE}" = "y" ]; then
    apt-get -qq --no-install-recommends --yes install python3-qrcode qrencode libpam-google-authenticator
    cp /root/google_auth.txt /home/${USERNAME}/.google_authenticator
    chmod 400 /home/${USERNAME}/.google_authenticator
    chown ${USERNAME}.${USERNAME} /home/${USERNAME}/.google_authenticator

    # Set pam to use google authenticator for ssh
    echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd
    sed -i "s/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/" /etc/ssh/sshd_config

    # Enable this to force use of token always, even with SSH key
    # sed -i "s/.*PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config
fi # GOOGLE_AUTH

update-initramfs -c -k all
update-grub

#_# # Not needed any more - boots cleanly without bpool being legacy
#_# # Only if encrypted disk
#_# if [ ${DISCENC} != "NOENC" ] ; then
#_#     # Fix filesystem mount ordering
#_#     zfs set mountpoint=legacy ${BPOOLNAME}/BOOT/${SUITE}
#_#     echo ${BPOOLNAME}/BOOT/${SUITE} /boot zfs \
#_#       nodev,relatime,x-systemd.requires=zfs-import-bpool.service 0 0 >> /etc/fstab
#_#     echo "${BPOOLNAME}/BOOT/grub /boot/grub zfs defaults,noatime 0 0" >> /etc/fstab
#_# else
#_#     echo "Not encrypted"
#_#     # echo "${POOLNAME}/boot/grub /boot/grub zfs defaults,noatime 0 0" >> /etc/fstab
#_# fi

# Add IP address to main tty issue
echo "IP = \4{eth0}" >> /etc/issue

# Set apt/dpkg to automagically snap the system datasets on install/remove
cat > /etc/apt/apt.conf.d/30pre-snap << EOF
# Snapshot main datasets before installing or removing packages
# We use a DATE variable to ensure all snaps have SAME date
# Dpkg::Pre-Invoke { "export DATE=\$(/usr/bin/date +%F-%H%M%S) ; /sbin/zfs snap ${POOLNAME}/ROOT/${SUITE}_${UUID}@apt_\${DATE}; /sbin/zfs snap ${BPOOLNAME}/BOOT/${SUITE}_${UUID}@apt_\${DATE}; /sbin/zfs snap ${BPOOLNAME}/BOOT/grub@apt_\${DATE}"; };

# Better version thanks rdurso - don't hard-code dataset UUIDs
# NOTE: For now BOOT/grub dataset does NOT have a UUID on it
# So datasets look like
# bpool/BOOT/focal_wsduhl
# bpool/BOOT/focal_wsduhl@apt_2021-11-07-184136
# bpool/BOOT/grub
# bpool/BOOT/grub@apt_2021-11-07-184136
# To use full UUID on BOOT/grub
#   change grep -E to use 'BOOT/.*_.{6}$')/grub@apt_${DATE}"

 Dpkg::Pre-Invoke { "export DATE=\$(/usr/bin/date +%F-%H%M%S) ; /sbin/zfs snap \$(/sbin/zfs list -o name | /usr/bin/grep -E 'ROOT/.*_.{6}$')@apt_\${DATE}; /sbin/zfs snap \$(/sbin/zfs list -o name | /usr/bin/grep -E 'BOOT/.*_.{6}$')@apt_\${DATE}; /sbin/zfs snap \$(/sbin/zfs list -o name | /usr/bin/grep -E 'BOOT/grub')@apt_\${DATE}"; };
EOF

# zfs set mountpoint=legacy rpool/var/log
# echo ${POOLNAME}/var/log /var/log zfs nodev,relatime 0 0 >> /etc/fstab
# 
# zfs set mountpoint=legacy rpool/var/spool
# echo ${POOLNAME}/var/spool /var/spool zfs nodev,relatime 0 0 >> /etc/fstab

zfs snapshot ${BPOOLNAME}/BOOT/${SUITE}_${UUID}@base_install
zfs snapshot ${BPOOLNAME}/BOOT/grub@base_install
zfs snapshot ${POOLNAME}/ROOT/${SUITE}_${UUID}@base_install

# End of Setup.sh
__EOF__

chmod +x ${ZFSBUILD}/root/Setup.sh

# Bind mount virtual filesystem, create Setup.sh, then chroot
mount --rbind /sys  ${ZFSBUILD}/sys
mount --make-rslave ${ZFSBUILD}/sys
mount --bind /dev  ${ZFSBUILD}/dev
mount -t proc /proc ${ZFSBUILD}/proc
# Make the mounts rslaves to make umounting later cleaner
# mount --make-rslave ${ZFSBUILD}/dev
# mount --make-rslave ${ZFSBUILD}/proc
# mount --make-rslave ${ZFSBUILD}/sys

# chroot and set up system
# chroot ${ZFSBUILD} /bin/bash --login -c /root/Setup.sh
unshare --mount --fork chroot ${ZFSBUILD} /bin/bash --login -c /root/Setup.sh

# Remove any lingering crash reports
rm -f ${ZFSBUILD}/var/crash/*

umount -n ${ZFSBUILD}/proc
umount -n ${ZFSBUILD}/dev
umount -n -R ${ZFSBUILD}/sys

# Copy setup log
cp /root/ZFS-setup.log ${ZFSBUILD}/home/${USERNAME}

# umount to be ready for export
zfs umount ${POOLNAME}/home/${USERNAME}
zfs umount ${POOLNAME}/docker
# With LUKS boot is in bpool pool
#DC# if [ ${DISCENC} = "LUKS" ] ; then
    zfs umount ${BPOOLNAME}/BOOT/grub
    zfs umount ${BPOOLNAME}/BOOT/${SUITE}_${UUID}
    zpool export ${BPOOLNAME}
#DC# else
#DC#     zfs umount ${POOLNAME}/boot/grub
#DC#     zfs umount ${POOLNAME}/boot/${SUITE}_${UUID}
#DC# fi
zfs umount ${POOLNAME}/ROOT/${SUITE}_${UUID}

# Back in livecd - unmount filesystems we may have missed
# Have to escape any / in path
ZFSBUILD_C=$(echo ${ZFSBUILD} | sed -e 's!/!\\/!'g)
# mount | grep -v zfs | tac | awk '/\/mnt/ {print \$3}' | xargs -i{} umount -lf {}
mount | grep -v zfs | tac | awk '/${ZFSBUILD_C}/ {print $3}' | xargs -i{} umount -lf {}
zpool export ${POOLNAME}


