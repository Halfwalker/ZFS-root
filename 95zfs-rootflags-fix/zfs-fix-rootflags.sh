#!/bin/bash

# Ubuntu 22.10 and earlier use a zfs mount that does not handle the
# casesensitive mount option. For systems building a 22.10 or lower
# install **while on a 23.04 or higher** system, we need to ensure
# that the 'casesensitive' option is removed from the kernel rootflags
# or commandline

# Fix casesensitive mount option for older ZFS versions
SYSROOT_MOUNT="/run/systemd/generator/sysroot.mount"

if [ -f "$SYSROOT_MOUNT" ]; then
    echo "zfs-rootflags-fix: Removing casesensitive from sysroot.mount" >> /dev/kmsg

    # Remove casesensitive from Options= line
    sed -i 's/,casesensitive//g; s/casesensitive,//g; s/^casesensitive$//g' "$SYSROOT_MOUNT"

    # Reload systemd to pick up the change
    systemctl daemon-reload

    echo "zfs-rootflags-fix: sysroot.mount modified and reloaded" >> /dev/kmsg
fi
