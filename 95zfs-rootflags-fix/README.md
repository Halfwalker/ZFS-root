# Dracut Module: zfs-rootflags-fix

## Purpose

This dracut module fixes boot failures on older Ubuntu/OpenZFS systems (22.10 and earlier) when booting from initramfs images generated on newer systems (23.04 and later) with OpenZFS 2.2+.

## The Problem

### Background

OpenZFS 2.2.0 (released October 2023) introduced support for the `casesensitive` mount option, which corresponds to the `casesensitivity` ZFS dataset property that has existed since earlier versions. When dracut or systemd generators detect this property on a dataset, they automatically add `casesensitive` to the mount flags.

However, older versions of `mount.zfs` (OpenZFS 2.1.x and earlier) do not recognize `casesensitive` as a valid mount option and will fail with an "invalid option" error.

### When This Occurs

This problem manifests when:

1. **ZFSBootMenu or initramfs** is built on a system with OpenZFS 2.2+ (e.g., Ubuntu 24.04)
2. **Target boot environment** runs OpenZFS 2.1.x or earlier (e.g., Ubuntu 22.04, 22.10, 20.04, 18.04)
3. The dracut-generated initramfs includes `casesensitive` in the rootflags

### Error Message

During boot, the system will fail, unable to mount `/sysroot`.

The system drops to a dracut emergency shell. You can see the following in `/run/initramfs/rdsosreport.txt` :
```
mount[464]: filesystem 'pool/ROOT/dataset' cannot be mounted due to invalid option 'casesensitive'.
mount[464]: Use the '-s' option to ignore the bad mount option.
```

## The Solution

This module provides two complementary fixes that run during the initramfs boot sequence:

1. **cmdline hook** (priority 00): Removes `casesensitive` from `/etc/cmdline.d/*` files before they're processed
2. **pre-mount hook** (priority 00): Removes `casesensitive` from the generated `/run/systemd/generator/sysroot.mount` unit file before systemd attempts to mount it

Both hooks run early enough to intercept the problematic option before the mount attempt.

## Affected Ubuntu Releases

### Releases That NEED This Fix

- Ubuntu 18.04 LTS (Bionic) - OpenZFS 0.7.x/0.8.x
- Ubuntu 20.04 LTS (Focal) - OpenZFS 0.8.x/2.0.x
- Ubuntu 22.04 LTS (Jammy) - OpenZFS 2.1.5
- Ubuntu 22.10 (Kinetic) - OpenZFS 2.1.5

### Releases That DON'T Need This Fix

- Ubuntu 23.04 (Lunar) and later - OpenZFS 2.2.x
- Ubuntu 24.04 LTS (Noble) and later - OpenZFS 2.2.x

## Installation

### Manual Installation

1. Copy the module directory to your dracut modules directory:
```bash
sudo cp -r 95zfs-rootflags-fix /usr/lib/dracut/modules.d/
```

2. Ensure all scripts are executable:
```bash
sudo chmod +x /usr/lib/dracut/modules.d/95zfs-rootflags-fix/*.sh
```

3. Rebuild your initramfs with the module included:
```bash
sudo dracut -f --add zfs-rootflags-fix
```

Or to rebuild all kernel initramfs images:
```bash
sudo dracut -f --add zfs-rootflags-fix --regenerate-all
```

### Automatic Inclusion

To automatically include this module in all future initramfs builds, create a dracut configuration file:

```bash
echo 'add_dracutmodules+=" zfs-rootflags-fix "' | sudo tee /etc/dracut.conf.d/zfs-rootflags-fix.conf
```

Then rebuild:
```bash
sudo dracut -f --regenerate-all
```

## Safety and Compatibility

**This module is safe to include on all systems**, regardless of OpenZFS version:

- ✅ Safe on systems that don't have the `casesensitive` option (no-op)
- ✅ Safe on systems with OpenZFS 2.2+ that support the option (no-op)
- ✅ Safe when booting datasets that were created on the same system version
- ✅ Only makes changes when the problematic option is actually present

The module's `sed` commands only remove `casesensitive` if found; otherwise they do nothing. There's no performance impact and no risk of breaking working configurations.

## Files in This Module

```
95zfs-rootflags-fix/
├── module-setup.sh          # Dracut module configuration
├── zfs-fix-cmdline.sh       # Hook: fixes /etc/cmdline.d/* files (cmdline phase)
├── zfs-fix-rootflags.sh     # Hook: fixes sysroot.mount unit (pre-mount phase)
└── README.md                # This file
```

## Verification

After booting a previously-failing dataset, you can verify the fix worked:

1. Check for the module's debug messages:
```bash
journalctl -b | grep "zfs-rootflags-fix"
```

2. Verify the system booted successfully (you should be at a normal prompt, not emergency shell)

3. Check that `/sysroot` was mounted:
```bash
mount | grep sysroot
```

## Use Case: ZFSBootMenu in Mixed Environments

This module is especially useful when using ZFSBootMenu to manage multiple boot environments across different Ubuntu versions. For example:

- ZFSBootMenu host: Ubuntu 24.04 (OpenZFS 2.2.x)
- Boot Environment 1: Ubuntu 24.04 (works fine)
- Boot Environment 2: Ubuntu 22.04 (needs this fix)
- Boot Environment 3: Ubuntu 20.04 (needs this fix)

With this module included in your ZFSBootMenu initramfs, all boot environments will work correctly regardless of their OpenZFS version.

## Technical Details

### Why `org.zfsbootmenu:rootflags` Doesn't Work

You might think setting the ZFS property `org.zfsbootmenu:rootflags` on the dataset would override the flags. However, the `casesensitive` option can be added by:

1. dracut's cmdline module reading ZFS dataset properties
2. systemd generators during initramfs execution
3. Files in `/etc/cmdline.d/` created during boot

These generation steps happen *during boot* in the initramfs, after the initramfs has already been created. The stored command line in the initramfs reflects the build-time system's ZFS version, which may include `casesensitive`.

### Hook Priority

Both hooks use priority `00` to run as early as possible:
- `cmdline 00`: Runs before cmdline processing
- `pre-mount 00`: Runs before any mounting, including `/sysroot`

This ensures the fix is applied before systemd attempts to use the problematic mount options.

## Troubleshooting

### Module Not Running

If the module doesn't seem to run, verify it's included:
```bash
lsinitrd /boot/initrd.img-$(uname -r) | grep zfs-rootflags-fix
```

You should see the module's files listed.

### Still Getting Mount Errors

If you still see mount errors:

1. Check that the hooks are executable in the initramfs
2. Verify the module is loaded: `lsinitrd | grep zfs-rootflags-fix`
3. Check journalctl output for hook execution messages
4. Ensure dracut was rebuilt after adding the module

## License

This module is provided as-is for use with dracut and ZFS on Linux systems.

## Contributing

If you find issues or have improvements, please contribute back to help others facing this compatibility challenge in mixed OpenZFS environments.
