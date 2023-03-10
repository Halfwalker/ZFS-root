# ZFS-root

This script is meant to be run from an Ubuntu Live CD.  It will build an Ubuntu system on the local system or VM using root-on-ZFS, with optional LUKS whole-disk encryption or ZFS native encryption.

The partition layout will look similar to this, depending on if a SWAP partition is needed for Hibernation and if encryption is selected.

```
Number  Start (sector)    End (sector)  Size       Code  Name
   1            2048        2050047    1000.0 MiB  EF00  BOOT_0
   2         2050048        ram size   x.x GiB     8200  SWAP_0  non-LUKS encrypted - OR
   2         2050048        ram size   x.x GiB     8309  SWAP_0  LUKS encrypted
   3        11290624        53052222   19.9 GiB    BF00  ZFS_0
```

*BOOT_0*
: Used for EFI and Syslinux booting.  Mounted at `/boot/efi`

*SWAP_0*
: Swap partition for use with Hibernate/Resume - only created if Hibernate is available and selected.  Will be encrypted if using LUKS.  Hibernate/Resume only uses the first disk for resume, no matter how many disks and swap partitions there are.  This means that the swap partitions must be at least the size of ram for Hibernate/Resume to work.

*ZFS_0*
: Partition for main ZFS pool.  Root dataset, /home dataset etc. all go in here.  NOTE: With ZFS native encryption the whole pool is NOT encrypted, only the main /rpool/ROOT and rpool/home container datasets.  This allows for non-encrypted datasets if desired.

## Features

* Will accommodate any number of disks for ZFS, and offer options for the raid level to be used.
* When using encryption it also installs [dropbear](https://matt.ucc.asn.au/dropbear/dropbear.html) to allow remote unlocking of system. `ssh -p 222 root@<ip addr>`
* Can pre-populate the main user `~.ssh/authorized_keys` with a pubkey pulled from named users from github.  This will also pre-populate the *dropbear* _authorized_keys_ if encryption is used.
* Optionally can install google_authenticator for the main user.  This will prompt for a TOTP code on login via ssh if no ssh-key is used.  The code and a QR code are displayed during initial config setup.
* If a local *apt-cacher* system is available it will point `apt` to that to speed up package downloads.
* Uses [zfsbootmenu](https://github.com/zbm-dev/zfsbootmenu/) to handle the actual booting of the ZFS pool.
* Memtest86+ included as a boot option.

*initramfs-tools* is NOT used, and is in fact disabled via `apt-mark hold initramfs-tools`.  Instead *dracut* is used for managing the initramfs.

## Configuration

The *ZFS-root.sh* script will prompt for all details it needs.  In addition, you can pre-seed those details via a *ZFS-root.conf* file, and an example is provided.  There are several extra config items that can only be set via a *ZFS-root.conf* file and not the menu questions.

NOTE: It will _always_ prompt for the list of disks to install to, and will pause with a textbox showing the selected options.

*SSHPUBKEY*
: Any SSH pubkey to add to the new system main user `~/.ssh/authorized_keys` file.

*HOST_ECDSA_KEY* or *HOST_RSA_KEY*
: Can specify the host ECDSA or RSA keys if desired.  Comes in handy for repeated runs of the script in testing, so you don't have to keep editing your `~/.ssh/known_hosts`.

## Booting details

The final root-on-ZFS install can be booted in a UEFI or Legacy Bios system - configurations for both are included.  While `efibootmgr` can be used to manage the UEFI boot slots, [rEFInd](https://www.rodsbooks.com/refind/) is much nicer and easier to use and configure.

In a multi-disk setup, the `/boot/efi` vfat filesystem for the ESP is set up as a multi-disk mirror using mdadm.  The mdadm mirror of all the *BOOT_n* vfat-formatted partitions (usually `/dev/md127`) is mounted at `/boot/efi`.  That way any changes to that directory is automagically replicated to all the ESP partitions.

That said, _rEFInd_ will find all of those ESP partitions and list them in the boot screen.  It doesn't matter which one you choose to boot from, they're all identical.  And once the system is fully booted, they're all mirrored and mounted under `/boot/efi`.


The boot sequence is as follows

### UEFI system

1. The UEFI system boots *rEFInd* which scans the EFI partition for bootable EFI images.  It and its config are in `/boot/efi/EFI/refind`.  The default boot option should be *zfsbootmenu*.
2. The *zfsbootmenu* image in `/boot/efi/EFI/zfsbootmenu` (consisting of _vmlinux-xxxxxx_ and _initramfs-xxxxxx.img_) is booted.  *zfsbootmenu* scans for any ZFS datasets that contain a `/boot` directory that contains recognizable kernel/initramfs pairs.
3. If the main ZFS pool is on LUKS-encrypted partitions, then an _early_stage_ script is run that prompts for a LUKS passphrase and attempts to unlock all LUKS-encrypted partitions.
4. If any dataset is ZFS-native encrypted, it will prompt for a passphrase.

A list of bootable datasets is presented, and it will boot the default one in 10 seconds.  Hitting *Escape* will present a menu of options, with lots of neat capabilities :

* Rollback any dataset
* Select a snapshot of a bootable dataset, create a clone and boot into that
* chroot into any bootable dataset
* Alter the kernel boot cmdline
* etc

### Syslinux system

The booting process is essentially the same, except Syslinux (in `/boot/efi/syslinux`) prompts for *zfsbootmenu*.  The Syslinux config file is in `/boot/efi/syslinux/syslinux.cfg`.

## More information

