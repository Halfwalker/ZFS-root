# ZFS-root

This script is meant to be run from an Ubuntu Live CD.  It will build an Ubuntu system on the local system or VM using root-on-ZFS, with optional LUKS whole-disk encryption or ZFS native encryption.  It can create a raidz or n-way mirror of disks to boot from.  UEFI SecureBoot with local keys is also available.

_Current issue: SecureBoot with locally-built kernel/initramfs for ZFSBootMenu is not working yet._

## tl;dr

- Boot an Ubuntu live-cd, like [ubuntu-24.04.1-live-server-amd64.iso](https://releases.ubuntu.com/noble/ubuntu-24.04.1-live-server-amd64.iso) and select *Try or install Ubuntu server*
- At the language selection prompt, type in `ctrl-z` to put the installer into the background and get a root shell
- Clone the **ZFS-root** repo
    ```
    git clone https://github.com/Halfwalker/ZFS-root.git
    ```
- Optionally copy the `ZFS-root.conf.example` to `ZFS-root.conf` and edit to suit.
- Run the `ZFS-root.sh` script - it will prompt for everything it needs.
    ```
    cd ZFS-root
    ./ZFS-root.sh
    ```

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

To add additional partitions, see the `ZFS-root.sh` script and search for 'Partition layout'.  Note that the last partition created (Main data partition for root) uses **:0:0** to tell `sgdisk` to use the rest of the space on the disk.  You will have to change that to **:0:+500G** for example to create a 500G partition.  Use whatever size you deem fit.

There is already **PARTITION_WIND** and **PARTITION_RCVR** variables defined to correctly number extra partitions, so use them to create the partitions.  Use **:0:0** to utilize the rest of the disk for the last partition.

For example, to create Window partitions for data (500G) and recovery (rest of disk), add these lines to the _Partition layout_ section after the _Main data partition for root_ lines.  Adjust the _Main data partition for root_ size as mentioned above, and set the Window partition size in the sample line below.

```
sgdisk -n ${PARTITION_WIND}:0:+500G -c ${PARTITION_WIND}:"WIN11_${disk}" -t ${PARTITION_WIND}:C12A /dev/disk/by-id/${zfsdisks[${disk}]}
sgdisk -n ${PARTITION_RCVR}:0:0     -c ${PARTITION_RCVR}:"RCVR_${disk}"  -t ${PARTITION_RCVR}:2700 /dev/disk/by-id/${zfsdisks[${disk}]}
```

NOTE: There may be problems with SecureBoot.  Your mileage may vary.

## Features

* Will accommodate any number of disks for ZFS, and offer options for the raid level to be used.
* Uses [zfsbootmenu](https://github.com/zbm-dev/zfsbootmenu/) to handle the actual booting of the ZFS pool.
* Can enable and configure UEFI SecureBoot using locally-generated keys.  The **rEFInd** binary and **zfsbootmenu** EFI bundle will be signed.
* Can optionally clone the installed ROOT dataset as a rescue dataset. This will be selectable in the **zfsbootmenu** menu in the event the main ROOT dataset ever gets corrupted.
* When using encryption it can also optionally install [dropbear](https://matt.ucc.asn.au/dropbear/dropbear.html) to allow remote unlocking of system. `ssh -p 222 root@<ip addr>`  **NOTE:** do not enable Dropbear for laptops - it wants to see the network in place, and if it's missing (usb-ethernet etc) then it will just sit and wait.
* Can pre-populate the main user `~/.ssh/authorized_keys` with a pubkey pulled from named users from github.  This will also pre-populate the *dropbear* _authorized_keys_ if encryption is used.
* Optionally can install google_authenticator for the main user.  This will prompt for a TOTP code on login via ssh if no ssh-key is used.  The code and a QR code are displayed during initial config setup.
* If a local *apt-cacher* system is available you can point `apt` to that to speed up package downloads.
* Memtest86+ included as a boot option.
* Optionally can install [zrepl](https://zrepl.github.io/) with a basic snapshot-only config to auto-snapshot the main and home datasets (see _/etc/zrepl_)
* [Packer](https://developer.hashicorp.com/packer) config to generate a *qcow2* KVM disk image for testing or CI/CD

*initramfs-tools* is NOT used, and is in fact disabled via `apt-mark hold initramfs-tools`.  Instead *dracut* is used for managing the initramfs.

## UEFI SecureBoot

For SecureBoot to be enabled and configured, the system must first be put into Setup Mode.  This will vary by system, but generally it means that any existing keys must be deleted in the bios config for UEFI SecureBoot.

[sbctl](https://github.com/Foxboron/sbctl) will be installed to manage the setup and configuration.  If the system is in Setup mode, the general process is as follows :

* **create-keys** : This will generate the local set of keys
* **enroll-keys --microsoft** : This enrolls the new keys _and_ the default Microsoft keys into the UEFI SecureBoot efi vars
* **sign** : Use the new keys to sign the various bootable bits

A **systemd-path** config is put in place in `/etc/systemd/system/zfsbootmenu-update*` and `/etc/systemd/system/refind-update*` wihch can watch the **zfsbootmenu** and **rEFInd** files.  If they ever change (eg. upgraded) then a new efi bundle is created and signed.  This way you don't have to remember to re-create and sign when you upgrade

## Configuration

The *ZFS-root.sh* script will prompt for all details it needs.  In addition, you can pre-seed those details via a *ZFS-root.conf* file, and an example is provided.  There are several extra config items that can only be set via a *ZFS-root.conf* file and not the menu questions.

> <dl>
>   <dt>SSHPUBKEY
>   <dd> Any SSH pubkey to add to the new system main user `~/.ssh/authorized_keys` file.
>   <dt>HOST_ECDSA_KEY or HOST_RSA_KEY
>   <dd> Can specify the host ECDSA or RSA keys if desired.  Comes in handy for repeated runs of the script in testing, so you don't have to keep editing your `~/.ssh/known_hosts`.
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
>   <dt>SOF_VERSION
>   <dd> Sound Open Firmware binaries (for laptops)
>   <dd> Default "2024.06"
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

This will run the `zfsbootmenu` command upon login automagically.  NOTE: one problem is that the ssh session remains after unlocking - need a clean way to ensure it exits after the unlock is finished

NOTE: Enabling encryption and Dropbear will _force_ the **ZFSBOOTMENU_BINARY_TYPE** in the config file to be **LOCAL**.  This will build _zfsbootmenu_ locally from scratch, including Dropbear into the _zfsbootmenu_ initramfs.

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

## Packer

A [Packer](https://developer.hashicorp.com/packer) configuration _ZFS-root_local.pkr.hcl_ is provided that will generate a `.qcow2` disk image for a typical simple install.  It can be run with a locally-installed packer/qemu setup, or with a docker container.

Both the local and docker methods use the _ZFS-root.conf.packerci_ config file for **ZFS-root.sh** to provide all the information for a local install.  The username/password is `packer/packer`.

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

Note: This makes use of a `vars` file to supply overrides to the packer config.  For example (replace `myuser` with your own username)

```
# Where to dump the resuling files
# NOTE: If running under docker this location must be bind-mounted in the docker run cmd below
#       The location is relative to INSIDE the container environment, so bind-mount like
#           -v /home/myuser/qemu:/home/myuser/qemu
output_prefix       = "/home/myuser/qemu/"

# false -> we can see the VM console gui
# true  -> console is hidden (required for docker)
headless            = false

ubuntu_version      = "24.04.1"

# Where to find the boot ISO - can be a local dir or URL
# The full name of the ISO is appended to this location
# NOTE: Like output_prefix, this path will be used INSIDE the container, so the
#       full path must be bind-mounted into the container with
#           -v /home/myuser/ISOs:/home/myuser/ISOs
ubuntu_live_iso_src = "file:///home/myuser/ISOs"
# or
# ubuntu_live_iso_src = "https://releases.ubuntu.com/24.04.1"
```

It will create a directory `.packer.d` in the repo that contains the packer qemu plugins - ignored via `.gitignore`.

The destination directory specified by `output_prefix` will contain a subdirectory like `packer_zfsroot_2024-10-17-1839)` with the disk image.

### Running packer via docker

A simple `Dockerfile` is provided to create a container based off the official Hashicorp packer image, with Qemu added.  That is in `packer/Dockerfile` and can be built locally with something like (replace *myname* with your user or other identifier)

```
docker build -t myname/packer-qemu packer
```

A sample run from the repo directory with docker would be (replace *myname* with your user or other identifier) like this

```
docker run --rm -it -v "$(pwd)":"${PWD}" -w "${PWD}" \
  --privileged --cap-add=ALL \
  -e PACKER_PLUGIN_PATH="${PWD}/.packer.d/plugins" \
  myname/packer-qemu init ZFS-root_local.pkr.hcl

# NOTE: If setting the output_prefix and/or ubuntu_live_iso_src in the ZFS-root_local.vars.hcl
#       file as above then must bind-mount that location in the docker container
#           -v /home/myuser/qemu:/home/myuser/qemu
#           -v /home/myuser/ISOs:/home/myuser/ISOs

docker run --rm -it -v "$(pwd)":"${PWD}" -w "${PWD}" \
  --privileged --cap-add=ALL \
  -v "${PWD}/.packer.d":/root/.cache/packer \
  -v "/home/myuser/qemu:/home/myuser/qemu" \
  -v /usr/share/OVMF:/usr/share/OVMF \
  -e PACKER_PLUGIN_PATH="${PWD}/.packer.d/plugins" \
  -e PACKER_LOG=1 \
  myname/packer-qemu build -var-file=ZFS-root_local.vars.hcl ZFS-root_local.pkr.hcl
```

The first `init` command only needs to be done once to download the packer qemu plugin.  Note: This does not use a `vars` file for packer, so will use the defaults in the `ZFS-root_local.pkr.hcl` packer config file.  That downloads the ISO to `.packer.d` and places the output directory (eg. `packer_zfsroot_2024-10-17-1839)` right in the current (repo) directory.

Of course you may pass in a `vars` file - if any directories are specified outside the repo directory they will have to be provided via `-v outside:inside` type volume mounts on the `docker run` command.

### Running the disk image

The `.qcow2` format disk image (here in *packer-zfsroot-2024-10-17-1839.qcow2*) may be run locally with commands like

* Ensure the local user owns the created files
    ```
    sudo chown -R ${USER}:${USER} packer-zfsroot-2024-10-17-1839
    ```

* Boot with syslinux, no UEFI
    ```
    kvm -no-reboot -m 2048 \
      -drive file=packer-zfsroot-2024-10-17-1839/packer-zfsroot-2024-10-17-1839.qcow2,format=qcow2,cache=writeback \
      -device virtio-scsi-pci,id=scsi0
    ```

* Boot with UEFI and locally generated *efivars.fd*
    ``` 
    kvm -no-reboot -m 2048 \
      -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
      -drive if=pflash,format=raw,readonly=on,file=packer_zfsroot_2024-10-17-1839/efivars.fd \
      -drive file=packer_zfsroot_2024-10-17-1839/packer-zfsroot-2024-10-17-1839.qcow2,format=qcow2,cache=writeback \
      -device virtio-scsi-pci,id=scsi0
    ```

## TODO

Things that are coming sooner or later ...

- Fix issue with SecureBoot and LOCAL locally generated kernel/initramfs.  While ZFSBootMenu loads and runs, it is unable to load the main system kernel in the ZFS pool
- Better additional partition handling - instead of editing the script, provide menus or `ZFS-root.conf` parameters to more easily set up Window partitions etc.
- Perhaps fetch SOF (Sound Open Firmware) versions to make available via menu
- Clean up Packer configs - it all works perfectly fine, but feels really cumbersome
- More shellcheck fixes

