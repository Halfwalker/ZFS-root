# ZFS-root

This script is meant to be run from an Ubuntu Live CD.  It will build an Ubuntu system on the local system or VM using root-on-ZFS, with optional LUKS whole-disk encryption or ZFS native encryption.  It can create a raidz or n-way mirror of disks to boot from.  UEFI SecureBoot with local keys is available, subject to the target firmware, keys, and setup state.

It can also be used to create a new `<poolname>/ROOT/<distro>` dataset for testing other Ubuntu distros on an existing system.  See **WIPE_FRESH** below.

_LOCAL ZFSBootMenu builds, including encrypted/Dropbear configurations, use the Podman `zbm-builder`. SecureBoot remains dependent on the intended firmware, enrolled keys, and setup, so test it on the target system._

## tl;dr

- Boot an Ubuntu live-cd, like [ubuntu-26.04-live-server-amd64.iso](https://releases.ubuntu.com/resolute/ubuntu-26.04-live-server-amd64.iso) and select *Try or install Ubuntu server*
- At the language selection prompt, hit `ctrl-z` to put the installer into the background and get a root shell
- Clone the **ZFS-root** repo
    ```
    git clone https://github.com/Halfwalker/ZFS-root.git
    ```
- Optionally copy the `ZFS-root.conf.example` to `ZFS-root.conf` and edit to suit.
    NOTE: The **WIPE_FRESH** parameter determines if this will be a full system wipe for a fresh install, or just the creation of a new distro dataset
    * `WIPE_FRESH=y`

      Wipe the selected disks and do a full clean install.  It will not touch unselected disks.

    * `WIPE_FRESH=n`

      Only create a new dataset like `<poolname>/ROOT/plucky` with a clean root install.  This will utilize the existing `/boot/efi` ESP partition mount, as well as the existing `<poolname>/home/<username>` default user home dataset/directory and `<poolname>/home/root` main _root_ user dataset/directory.  The new dataset will be selectable via ZFSBootMenu

- Run the `ZFS-root.sh` script - it will prompt for everything it needs.  You can create a `ZFS-root.conf` from the example `ZFS-root.conf.example` or specify another configfile with `-c <file>` to provide default values.
    ```
    cd ZFS-root
    ./ZFS-root.sh  (defaults to `ZFS-root.conf` if it exists)
    ```

## Parameters

You can add a couple of parameters on the command-line

- `-c <config file>`

    Pass in a specific config file to override the default `ZFS-root.conf`

- `-p`

    Packer build mode.  Uses `ZFS-root.conf.packerci` unless overridden with `-c`.  Config overrides can be passed via `--set KEY=VALUE` in `run-packer.sh`.  See [README-PACKER.md](README-PACKER.md).

- `-d`

    Enable DEBUG mode - literally just `set -x` in the script to see everything it does

## Partition layout

The partition layout will look similar to this, depending on if a SWAP partition is needed for Hibernation and if encryption is selected.  The **_0** refers to the disk number.  **_0** for first disk, **_1** for second and so on.

```
Number  Start (sector)  End        Size        Code  Name
   1          2048      2050047    1000.0 MiB  EF00  BOOT_EFI_0
   2       2050048      ram size   x.x GiB     8200  SWAP_0      non-LUKS encrypted - OR
   2       2050048      ram size   x.x GiB     8309  SWAP_0      LUKS encrypted
   3      11290624      53052222   19.9 GiB    BF00  ZFS_0
```

> <dl>
>     <dt>BOOT_EFI_0
>     <dd>Used for EFI and Syslinux booting.  Mounted at `/boot/efi`  For multi-disk raidz this will be a mdadm mirror across all the disks.
>     <dt>SWAP_0
>     <dd>Swap partition for use with Hibernate/Resume - only created if Hibernate is available and selected.  Will be encrypted if using LUKS.  Hibernate/Resume only uses the first disk for resume, no matter how many disks and swap partitions there are.  This means that the swap partitions must be at least the size of ram for Hibernate/Resume to work.
>     <dt>ZFS_0
>     <dd>Partition for main ZFS pool.  Root dataset, /home dataset etc. all go in here.  NOTE: With ZFS native encryption the whole pool is NOT encrypted, only the main rpool/ROOT and rpool/home container datasets.  This allows for non-encrypted datasets if desired.
> </dl>

### Additional partitions

To add additional partitions, see the `ZFS-root.sh` script and search for '_Partition layout_' in the `partition_disks()` function.  Note that the last partition created (Main data partition for root) uses **:0:0** to tell `sgdisk` to use the rest of the space on the disk.  You will have to change that to **:0:+500G** for example to create a 500G partition.  Use whatever size you deem fit.

There is already **PARTITION_WIND** and **PARTITION_RCVR** variables defined to correctly number extra partitions, so use them to create the partitions.  Use **:0:0** to utilize the rest of the disk for the last partition.

For example, to create Windows partitions for data (500G) and recovery (rest of disk), add these lines to the _Partition layout_ section after the _Main data partition for root_ lines.  Adjust the _Main data partition for root_ size as mentioned above, and set the Window partition size in the sample line below.

```
sgdisk -n ${PARTITION_WIND}:0:+500G -c ${PARTITION_WIND}:"WIN11_${disk}" -t ${PARTITION_WIND}:C12A /dev/disk/by-id/${zfsdisks[${disk}]}
sgdisk -n ${PARTITION_RCVR}:0:0     -c ${PARTITION_RCVR}:"RCVR_${disk}"  -t ${PARTITION_RCVR}:2700 /dev/disk/by-id/${zfsdisks[${disk}]}
```

NOTE: SecureBoot requires compatible firmware, enrolled keys, and the appropriate setup state; validate it on the intended target. Your mileage may vary.

## Datasets

Using a clean (**WIPE_FRESH=y**) install of Ubuntu Resolute/26.04 as an example, the following ZFS datasets would be created

- _**`<poolname>/ROOT`**_
    > Container for all root datasets.  This may contain multiple full root installs, of different - or the same - Ubuntu distro versions.
    > If ZFS encryption is enabled, this container will be encrypted so all child root datasets will also be encrypted.  The passphrase must be entered on the console (or via Dropbear) when ZFSBootMenu attempts to boot any root dataset under this.
- _**`<poolname>/ROOT/resolute`**_
    > Root install dataset for Ubuntu Resolute/26.04.  This will be a full install of Resolute/26.04 _without_ the home directory of the main user or root user.  Or `/boot/efi` which is the ESP partition mentioned above - that is simply mounted when the system boots.
    > This root dataset will be set as the ZFSBootMenu default via the **bootfs** option for the `<poolname>` pool.  See the `create_zfs_datasets()` function.
- _**`<poolname>/ROOT/resolute@base_install`**_
    > Snapshot of the main Resolute root dataset, as of the completion of the install.
- _**`<poolname>/ROOT/resolute_rescue_base`**_
    > Clone of the Resolute **base_install** snapshot.  In the event of real problems, one can boot into this for a working system.
- _**`<poolname>/ROOT/resolute@apt_2026-07-06-190000`**_
    > Automatic snapshots taken before any `apt install <package>` or other **apt** operation that modifies the system.
- _**`<poolname>/home`**_
    > Container for all home user datasets.  If ZFS encryption is enabled, this container and all child datasets will be encrypted using the key `/etc/zfs/zroot.homekey`.  This key is safe because it's housed in an encrypted dataset (`<poolname>/ROOT/resolute`) so cannot be accessed until the main system is decrypted.
- _**`<poolname>/home/root`**_
    > Main root user home dataset/directory - `/root`
- _**`<poolname>/home/<username>`**_
    > Main user home dataset/directory - `/home/<username`
- _**`<poolname>/ROOT/swap`**_
    > For non-LUKS encrypted or non-HIBERNATE enabled systems, a swap dataset is created instead.
- _**`<poolname>/docker`**_
    > With **Docker** using a dedicated dataset is recommended.

If a subsequent run is made with **WIPE_FRESH=n** then a new root dataset will be created.  For example, one could install Ubuntu Plucky/25.04 on an existing Resolute/26.04 system

- _**`<poolname>/ROOT/plucky`**_
    > Root install dataset for Ubuntu Plucky/25.04.  If ZFS encryption was enabled for the Resolute/26.04 main system, then this dataset will inherit that and also be encrypted.
- _**`<poolname>/ROOT/plucky@base_install`**_
    > Snapshot of the Plucky root dataset, as of the completion of the install.
- _**`<poolname>/ROOT/plucky_rescue_base`**_
    > Clone of the Plucky **base_install** snapshot.  In the event of real problems, one can boot into this for a working system.

To change the ZFSBootMenu default dataset to boot from the original Resolute/26.04 to the new Plucky/25.04

> `zfs set bootfs=<poolname>/ROOT/plucky <poolname>`

## Features

* Will accommodate any number of disks for ZFS, and offer options for the raid level to be used.
* Uses [zfsbootmenu](https://github.com/zbm-dev/zfsbootmenu/) to handle the actual booting of the ZFS root dataset(s).
* Can enable and configure UEFI SecureBoot using locally-generated keys.  The **rEFInd** binary and **zfsbootmenu** EFI bundle will be signed.
* Can optionally clone the installed ROOT dataset as a rescue dataset. This will be selectable in the **zfsbootmenu** menu in the event the main ROOT dataset ever gets corrupted.
* When using encryption it can also optionally install [dropbear](https://matt.ucc.asn.au/dropbear/dropbear.html) to allow remote unlocking of system. `ssh -p 222 root@<ip addr>`  **NOTE:** do not enable Dropbear for laptops - it wants to see the network in place, and if it's missing (usb-ethernet etc) then it will just sit and wait.
* Can pre-populate the main user `~/.ssh/authorized_keys` with a pubkey pulled from named users from github.  This will also pre-populate the *dropbear* _authorized_keys_ if encryption is used.
* Optionally can install google_authenticator for the main user.  This will prompt for a TOTP code on login via ssh if no ssh-key is used.  The code and a QR code are displayed during initial config setup.
* If a local *apt-cacher* system is available you can point `apt` to that to speed up package downloads.
* Memtest86+ included as a boot option.
* Optionally can install [zrepl](https://zrepl.github.io/) with a basic snapshot-only config to auto-snapshot the main and home datasets (see _/etc/zrepl_)
* [Packer](https://developer.hashicorp.com/packer) config to generate *QCOW2* KVM disk images for testing or CI/CD by default, with opt-in ephemeral RAM-backed raw disks. See [README-PACKER.md](README-PACKER.md) for operations.


*initramfs-tools* is NOT used, and is in fact disabled via `apt-mark hold initramfs-tools`.  Instead *dracut* is used for managing the initramfs.

## UEFI SecureBoot

For SecureBoot to be enabled and configured, the system must first be put into Setup Mode.  This will vary by system, but generally it means that any existing keys must be deleted in the bios config for UEFI SecureBoot.  For Virtualbox you can delete the `.nvram` file before starting the VM.  You will have to hit `del` to get into the bios, get to the SecureBoot section and delete the keys.  There is an option to do this in the Virtualbox gui, but it doesn't seem to work (needs a magic incantation/process), doing it directly in the bios works.

[sbctl](https://github.com/Foxboron/sbctl) will be installed to manage the setup and configuration.  If the system is in Setup mode, the general process is as follows :

* **create-keys** : This will generate the local set of keys
* **enroll-keys --microsoft** : This enrolls the new keys _and_ the default Microsoft keys into the UEFI SecureBoot efi vars
* **sign** : Use the new keys to sign the various bootable bits

A **systemd-path** config is put in place in `/etc/systemd/system/zfsbootmenu-update*` and `/etc/systemd/system/refind-update*` wihch can watch the **zfsbootmenu** and **rEFInd** files.  If they ever change (eg. upgraded) then a new efi bundle is created and signed.  This way you don't have to remember to re-create and sign when you upgrade

Set **AUTOSIGN=n** in your config to disable this — useful for testing when you want to manage signing manually.

## Configuration

The *ZFS-root.sh* script will prompt for all details it needs.  In addition, you can pre-seed those details via a *ZFS-root.conf* file, and an example is provided.  There are several extra config items that can only be set via a *ZFS-root.conf* file and not the menu questions.

> <dl>
>   <dt>SSHPUBKEY
>   <dd> Any SSH pubkey to add to the new system main user `~/.ssh/authorized_keys` file.
>   <dt>HOST_ECDSA_KEY and HOST_ECDSA_KEY_PUB
>   <dd> Can specify a predefined host ECDSA key if desired.  Comes in handy for repeated runs of the script in testing, so you don't have to keep editing your `~/.ssh/known_hosts`.
>   <dt>HOST_RSA_KEY and HOST_RSA_KEY_PUB
>   <dd> Predefined Host RSA key and associated pubkey
>   <dt>HOST_ED25519_KEY and HOST_ED25519_KEY_PUB
>   <dd> Predefined Host ed25519 key and associated pubkey
> </dl>

There are a few parameters that are defaulted in the script, but can be overridden in the `ZFS-root.conf` file

> <dl>
>   <dt>ZFSBOOTMENU_BINARY_TYPE
>   <dd>
>     <dl>
>       <dt>EFI
>       <dd>Pulls ZFSBootmenu efi image
>       <dt>KERNEL
>       <dd>Pulls ZFSBootmenu kernel/initramfs set
>       <dt>LOCAL
>       <dd>Pulls full git repo and builds kernel/initramfs locally
>     </dl>
>   <dt>ZFSBOOTMENU_REPO_TYPE
>   <dd>
>     <dl>
>       <dt>TAGGED
>       <dd>Pulls the latest stable release
>       <dt>GIT
>       <dd>Pulls the latest full repo, which may be in flux
>     </dl>
>   <dt>ZFSBOOTMENU_CMDLINE
>   <dd>Extra options for the ZFSBootMenu boot command-line.  The default here disables the hook script that sometimes kills power to USB ports.  See the ZFS-root.conf.example file
>   <dd>Default "zbm.skip_hooks=90-xhci-unbind.sh"
>   <dt>AUTOSIGN
>   <dd> Controls auto-signing of rEFInd and ZFSBootMenu EFI bundles when boot files change.  Requires SecureBoot.
>   <dd> Default "y" in ZFS-root.conf.example, "n" in ZFS-root.conf.packerci
>   <dt>SOF_VERSION
>   <dd> Sound Open Firmware binaries (for laptops)
>   <dd> Default "2025.05.1"
> </dl>

NOTE: It will _always_ prompt for the list of disks to install to, and will pause with a textbox showing the selected options.

### zrepl ZFS snapshot management and replication

The simple *zrepl* config install sets up two snapshot/prune only jobs, no replication.  Both the main root dataset and the home user dataset are snap'd on a 15min cadence.  The root dataset prune policy is to keep 1 hour of 15min snaps, 24 hourly and 14 daily.  The home user dataset policy is similar, 1 hour of 15min snaps, 24 hourly and 30 daily snaps.

In addition, the root dataset is only snap'd if there has been more that 120mb written to it - the idea being that we don't _really_ need mostly-empty snaps of an idle system.  Home data though, snap them all ...

The snapshot config uses _/usr/local/bin/zrepl_threshold.sh_ to determine whether or not to snap.  It reads the *com.zrepl:snapshot-threshold* property in a dataset for the threshold value to compare against the *written* property.

For any dataset that you want a threshold set, use something similar to

```
sudo zfs set com.zrepl:snapshot-threshold=120000000 rpool/ROOT/noble
```

### Sample SSH config for Dropbear

If using Dropbear for remote unlocking of an encrypted system, a sample `~/.ssh/config` entry could look like this

```
Host unlock-foobox
    Hostname foobox.example.com
    User root
    Port 222
    IdentityFile ~/.ssh/unlock_luks
    HostKeyAlgorithms ssh-rsa
    RequestTTY yes
    RemoteCommand zfsbootmenu
```

This will run the `zfsbootmenu` command upon login automagically.  NOTE: one problem is that the ssh session might remain after unlocking - need a clean way to ensure it exits after the unlock is finished

NOTE: Enabling encryption and Dropbear will _force_ the **ZFSBOOTMENU_BINARY_TYPE** in the config file to be **LOCAL**.  This will build _zfsbootmenu_ locally from scratch, including Dropbear into the _zfsbootmenu_ initramfs.  LOCAL builds now use the zbm-builder **podman** container to generate the kernel/initramfs pair, required on 26.04+ and recommended for consistency across releases.

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

The `syslinux.cfg` file is generated by the script `syslinux-update.sh` which is found in either of these locations
* `/boot/efi/syslinux-update.sh`
* `/etc/zfsbootmenu/generate-zbm.post.d/syslinux-update.sh`

## TODO

Things that are coming sooner or later ...

- Continue validating SecureBoot combinations on their intended firmware, key enrollment, and setup state
- Better additional partition handling - instead of editing the script, provide menus or `ZFS-root.conf` parameters to more easily set up Window partitions etc.
- Perhaps fetch SOF (Sound Open Firmware) versions to make available via menu
- More shellcheck fixes
