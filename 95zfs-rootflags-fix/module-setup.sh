#!/bin/bash

# Ubuntu 22.10 and earlier use a zfs mount that does not handle the
# casesensitive mount option. For systems building a 22.10 or lower
# install **while on a 23.04 or higher** system, we need to ensure
# that the 'casesensitive' option is removed from the kernel rootflags
# or commandline

check() {
    return 0
}

depends() {
    echo systemd
}

install() {
    # Run cmdline fix very early
    inst_hook cmdline 00 "$moddir/zfs-fix-cmdline.sh"
    # Run sysroot.mount fix in pre-mount
    inst_hook pre-mount 00 "$moddir/zfs-fix-rootflags.sh"
}
