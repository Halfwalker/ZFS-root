#!/bin/bash

# Ubuntu 22.10 and earlier use a zfs mount that does not handle the
# casesensitive mount option. For systems building a 22.10 or lower
# install **while on a 23.04 or higher** system, we need to ensure
# that the 'casesensitive' option is removed from the kernel rootflags
# or commandline

# Fix casesensitive in cmdline.d files
for cmdfile in /etc/cmdline.d/*; do
    if [ -f "$cmdfile" ]; then
        if grep -q "casesensitive" "$cmdfile"; then
            echo "zfs-rootflags-fix: Removing casesensitive from $cmdfile" >> /dev/kmsg
            sed -i 's/,casesensitive//g; s/casesensitive,//g' "$cmdfile"
        fi
    fi
done
