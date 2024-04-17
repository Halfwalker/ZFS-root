# ZFS-root

This script is meant to be run from an Ubuntu Live CD.  It will build an Ubuntu system on the local system or VM using root-on-ZFS, with optional LUKS whole-disk encryption or ZFS native encryption.

## tl;dr

- Boot an Ubuntu live-cd, like [ubuntu-22.04.4-live-server-amd64.iso](https://releases.ubuntu.com/jammy/ubuntu-22.04.4-live-server-amd64.iso) and select *Try or install Ubuntu server*
- At the language selection prompt, type in `ctrl-z` to put the installer into the background and get a root shell
- Clone the **ZFS-root** repo
    ```
    git clone https://github.com/Halfwalker/ZFS-root.git
    ```
- Run the `ZFS-root.sh` script - it will prompt for everything it needs.
    ```
    cd ZFS-root
    ./ZFS-root.sh
    ```

The partition layout will look similar to this, depending on if a SWAP partition is needed for Hibernation and if encryption is selected.  The **_0** refers to the disk number.  **_0** for first disk, **_1** for second and so on.

```
Number  Start (sector)    End (sector)  Size       Code  Name
   1            2048        2050047    1000.0 MiB  EF00  BOOT_0
   2         2050048        ram size   x.x GiB     8200  SWAP_0  non-LUKS encrypted - OR
   2         2050048        ram size   x.x GiB     8309  SWAP_0  LUKS encrypted
   3        11290624        53052222   19.9 GiB    BF00  ZFS_0
```

> <dl>
>     <dt>BOOT_0
>     <dd>Used for EFI and Syslinux booting.  Mounted at `/boot/efi`
>     <dt>SWAP_0
>     <dd>Swap partition for use with Hibernate/Resume - only created if Hibernate is available and selected.  Will be encrypted if using LUKS.  Hibernate/Resume only uses the first disk for resume, no matter how many disks and swap partitions there are.  This means that the swap partitions must be at least the size of ram for Hibernate/Resume to work.
>     <dt>ZFS_0
>     <dd>Partition for main ZFS pool.  Root dataset, /home dataset etc. all go in here.  NOTE: With ZFS native encryption the whole pool is NOT encrypted, only the main rpool/ROOT and rpool/home container datasets.  This allows for non-encrypted datasets if desired.
> </dl>

## Features

* Will accommodate any number of disks for ZFS, and offer options for the raid level to be used.
* Uses [zfsbootmenu](https://github.com/zbm-dev/zfsbootmenu/) to handle the actual booting of the ZFS pool.
* Can optionally clone the installed ROOT dataset as a rescue dataset. This will be selectable in the **zfsbootmenu** menu in the event the main ROOT dataset ever gets corrupted.
* When using encryption it can also optionally install [dropbear](https://matt.ucc.asn.au/dropbear/dropbear.html) to allow remote unlocking of system. `ssh -p 222 root@<ip addr>`  **NOTE:** do not enable Dropbear for laptops - it wants to see the network in place, and if it's missing (usb-ethernet etc) then it will just sit and wait.
* Can pre-populate the main user `~/.ssh/authorized_keys` with a pubkey pulled from named users from github.  This will also pre-populate the *dropbear* _authorized_keys_ if encryption is used.
* Optionally can install google_authenticator for the main user.  This will prompt for a TOTP code on login via ssh if no ssh-key is used.  The code and a QR code are displayed during initial config setup.
* If a local *apt-cacher* system is available you can point `apt` to that to speed up package downloads.
* Memtest86+ included as a boot option.
* Optionally can install [zrepl](https://zrepl.github.io/) with a basic snapshot-only config to auto-snapshot the main and home datasets (see _/etc/zrepl_)
* [Packer](https://developer.hashicorp.com/packer) config to generate a *qcow2* KVM disk image for testing or CI/CD

*initramfs-tools* is NOT used, and is in fact disabled via `apt-mark hold initramfs-tools`.  Instead *dracut* is used for managing the initramfs.

## Configuration

The *ZFS-root.sh* script will prompt for all details it needs.  In addition, you can pre-seed those details via a *ZFS-root.conf* file, and an example is provided.  There are several extra config items that can only be set via a *ZFS-root.conf* file and not the menu questions.

> <dl>
>   <dt>SSHPUBKEY
>   <dd> Any SSH pubkey to add to the new system main user `~/.ssh/authorized_keys` file.
>   <dt>HOST_ECDSA_KEY or HOST_RSA_KEY
>   <dd> Can specify the host ECDSA or RSA keys if desired.  Comes in handy for repeated runs of the script in testing, so you don't have to keep editing your `~/.ssh/known_hosts`.
> </dl>

NOTE: It will _always_ prompt for the list of disks to install to, and will pause with a textbox showing the selected options.

### zrepl ZFS snapshot management and replication

The simple *zrepl* config install sets up two snapshot/prune only jobs, no replication.  Both the main root dataset and the home user dataset are snap'd on a 15min cadence.  The root dataset prune policy is to keep 1 hour of 15min snaps, 24 hourly and 14 daily.  The home user dataset policy is similar, 1 hour of 15min snaps, 24 hourly and 30 daily snaps.

In addition, the root dataset is only snap'd if there has been more that 120mb written to it - the idea being that we don't _really_ need mostly-empty snaps of an idle system.  Home data though, snap them all ...

The snapshot config uses _/usr/local/bin/zrepl_threshold.sh_ to determine whether or not to snap.  It reads the *com.zrepl:snapshot-threshold* property in a dataset for the threshold value to compare against the *written* property.

For any dataset that you want a threshold set, use something similar to

```
sudo zfs set com.zrepl:snapshot-threshold=120000000 rpool/ROOT/jammy
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

This will run the `zfsbootmenu` command upon login automagically.  NOTE: one problem is that the ssh session remains after unlocking - need a clean way to ensure it exits after the unlock is finished

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

## Packer

A [Packer](https://developer.hashicorp.com/packer) configuration (_ZFS-root_local.pkr.hcl_) is provided that will generate a `.qcow2` disk image for a typical simple install.  It can be run with a locally-installed packer/qemu setup, or with a docker container.

### Running packer locally

Packer and QEMU will need to be installed

```
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update
sudo apt install packer qemu-kvm qemu-utils ovmf
```

To run locally, a command like

```
packer build -var-file=ZFS-root_local.vars.hcl ZFS-root_local.pkr.hcl
```

Note: This makes use of a `vars` file to supply overrides to the packer config.  For example

```
# Where to dump the resuling files
output_prefix       = "/home/myuser/qemu/"

# false -> we can see the VM console gui
# true  -> console is hidden
headless            = false

ubuntu_version      = "22.04.1"

# Usually set to "" as the entire src dir is specified in ubuntu_live_iso_src
ubuntu_version_dir  = ""

# Where to find locally downloaded ISOs
ubuntu_live_iso_src = "file:///home/myuser/ISOs"
```

This uses the _ZFS-root-packerci.conf_ config file for **ZFS-root.sh** to provide all the information for a local install.  The username/password is `packer/packer`.

It will create a directory `.packer.d` in the repo that contains the packer qemu plugins - ignored via `.gitignore`.

The destination directory specified by `output_prefix` will contain a subdirectory like `packer_zfsroot_2023-07-24-1104` with the disk image.

### Running packer via docker

A simple `Dockerfile` is provided to create a container based off the official Hashicorp packer image, with Qemu added.  That is in `packer/Dockerfile` and can be built locally with something like

```
docker build -t myname/packer-qemu packer
```

A sample run from the repo directory with docker would be

```
docker run --rm -it -v "$(pwd)":"${PWD}" -w "${PWD}" \
  --privileged --cap-add=ALL \
  -e PACKER_PLUGIN_PATH="${PWD}/.packer.d/plugins" \
  myname/packer-qemu init ZFS-root_local.pkr.hcl

docker run --rm -it -v "$(pwd)":"${PWD}" -w "${PWD}" \
  --privileged --cap-add=ALL \
  -v "${PWD}/.packer.d":/root/.cache/packer \
  -v /usr/share/OVMF:/usr/share/OVMF \
  -e PACKER_PLUGIN_PATH="${PWD}/.packer.d/plugins" \
  -e PACKER_LOG=1 \
  myname/packer-qemu build ZFS-root_local.pkr.hcl
```

The first `init` command only needs to be done once to download the packer qemu plugin.  Note: This does not use a `vars` file for packer, so will use the defaults in the `ZFS-root_local.pkr.hcl` packer config file.  That downloads the ISO to `.packer.d` and places the output directory (eg. `packer_zfsroot_2023-07-24-1104)` right in the current (repo) directory.

Of course you may pass in a `vars` file - if any directories are specified outside the repo directory they will have to be provided via `-v outside:inside` type volume mounts on the `docker run` command.

### Running the disk image

The `.qcow2` format disk image may be run locally with a command like

```
kvm -no-reboot -m 2048 -drive file=packer-zfsroot-2023-07-23-2233,format=qcow2,cache=none -device virtio-scsi-pci,id=scsi0
```

