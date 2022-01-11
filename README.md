# ZFS-root

This script is meant to be run from an Ubuntu Live CD.  It will build an Ubuntu system on the local system or VM using root-on-ZFS, with optional LUKS whole-disk encryption or ZFS native encryption.

If disk encryption via LUKS is selected, the partition layout will look similar to

```
Number  Start (sector)    End (sector)  Size       Code  Name
   1              48            2047   1000.0 KiB  EF02  GRUB_0
   2            2048         1050623   512.0 MiB   EF00  UEFI_0
   3         1050624         3098623   1000.0 MiB  BF01  BOOT_0
   4         3098624        11290623   3.9 GiB     8300  SWAP_0
   5        11290624        53052222   19.9 GiB    8300  ZFS_0
```

*GRUB_0* 
: A standard grub partition for booting.  This is mounted at `/boot`

*UEFI_0*
: If EFI booting is required this partition will hold the UEFI data.  Mounted at `/boot/efi`

*BOOT_0*
: Small boot partition - must be unencrypted.  Just holds kernel and mountpoints for grub and uefi (if used).

*SWAP_0*
: Swap partition for use with Hibernate/Resume.  Will be encrypted if using LUKS.  Hibernate/Resume only works with a single disk currently.

*ZFS_0*
: Partition for main ZFS pool.  Root dataset, /home dataset etc. all go in here.  Will be encrypted for LUKS, but not with ZFS native encryption which uses per-dataset encryption.

## Features

* Will accommodate any number of disks for ZFS, and offer options for the raid level to be used.
* When using encryption it also installs [dropbear](https://matt.ucc.asn.au/dropbear/dropbear.html) to allow remote unlocking of system. `ssh -p 2222 root@<ip addr>`
* Can pre-populate the main user `~.ssh/authorized_keys` with a pubkey pulled from named users from github.  This will also pre-populate the *dropbear* _authorized_keys_ if encryption is used.
* Optionally can install google_authenticator for the main user.  This will prompt for a TOTP code on login via ssh if no ssh-key is used.  The code and a QR code are displayed during initial config setup.
* If a local *apt-cacher* system is available it will point `apt` to that to speed up package downloads.
