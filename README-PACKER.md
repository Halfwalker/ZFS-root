# Packer builds

`run-packer.sh` builds ZFS-root KVM images with [Packer](https://developer.hashicorp.com/packer); `run-kvm.sh` boots them. Normal builds remain QCOW2. `--ramdisk SIZE` is an explicit alternative for ephemeral, tmpfs-backed raw disks.

Packer-built images use `packer/packer` creds by default.

## Quick start

Build a direct QCOW2 image:

```bash
./run-packer.sh --ubuntu-version 24.04.2 --discenc NOENC --disk-size 5G

./run-kvm.sh /qemu/builds/packer-noble-NOENC-<timestamp>  # to directly boot a specific build
./run-kvm.sh  # to choose which build to boot from a list
```

Build the same QCOW2 image through Docker:

```bash
./run-packer.sh --docker --ubuntu-version 24.04.2 --discenc NOENC --disk-size 5G
./run-kvm.sh /qemu/builds/packer-noble-NOENC-<timestamp>
```

More examples
```bash
# Two-disk mirror with SecureBoot
./run-packer.sh --ubuntu-version 24.04.2 --discenc NOENC --disk-size 5G \
    --disks 2 --raidlevel mirror --secureboot

# Three-disk raidz1 with ZFS encryption and custom hostname
./run-packer.sh --ubuntu-version 24.04.2 --discenc ZFSENC --disk-size 10G \
    --disks 3 --raidlevel raidz1 --set MYHOSTNAME=securebox
```

## Build modes and host prerequisites

**Direct mode** uses the host Packer and QEMU/KVM. It can display the installer console when `DISPLAY` is available; otherwise it runs headless.

**Docker mode** runs Packer in a privileged container and is always headless. It requires a running Docker daemon (and Docker group access when running as a non-root user), `/dev/kvm`, writable `/qemu/builds`, readable `/qemu/ISOs`, and OVMF firmware. The Packer plugin cache must be available to the selected mode. Docker mode also needs the container capability to use the mounted KVM device and paths.

Both modes require KVM and compatible OVMF firmware. The scripts select the available 4 MiB OVMF files when present and fall back to the older 2 MiB names. On hosts with kernels older than 6, use the repository's QEMU 8.1.5 compatibility path where required.

## Build options

| Option | Description |
| --- | --- |
| `--docker` | Run Packer in Docker; always headless |
| `--ubuntu-version VERSION` | Ubuntu version, for example `24.04.2` or `26.04` |
| `--ubuntu-name NAME` | Release name; otherwise derived from the version |
| `--discenc NOENC\|ZFSENC\|LUKS` | Disk-encryption mode |
| `--disk-size SIZE` | Per-disk size, for example `5G` |
| `--disks N` / `--raidlevel LEVEL` | Multi-disk count and `mirror` or `raidz1` layout |
| `--secureboot` | Select SecureBoot OVMF where available and set `SECUREBOOT=y`; target firmware/key setup still needs validation |
| `--iso-src URL` | ISO source, for example `file:///qemu/ISOs` |
| `--config FILE` | ZFS-root preseed file; default is `ZFS-root.conf.packerci` |
| `--set KEY=VALUE` | Override a preseed configuration value; repeat as needed |
| `--ramdisk SIZE` | Opt in to host-tmpfs staging and raw disks. Requires sudo/tmpfs support and explicit cleanup after use. |

## RAM-backed raw builds

Use RAM mode only when the raw disks can or should be temporary: (eg. for CI/CD build/validation)

```bash
./run-packer.sh --ramdisk 16G --ubuntu-version 24.04.2 --discenc ZFSENC --disk-size 8G
```

The wrapper mounts a host tmpfs at `/qemu/builds/.ramdisk-work/<build>.work`, then Packer stages its output there. After a successful build it creates the normal final directory, `/qemu/builds/packer-<release>-<encryption>-<timestamp>-<pid>/`, copies persistent metadata and logs into it, and file-bind-mounts each raw disk at its final parent path. The raw disk is therefore directly beside the other artifacts, for example:

```text
/qemu/builds/packer-jammy-ZFSENC-<timestamp>-<pid>/
├── packer-jammy-ZFSENC-<timestamp>-<pid>.raw
├── build-metadata.txt
├── efivars.fd
└── packer-output.log
```

The staging mount is removed after promotion (bind-mount ramdisk into final location), but its raw-file inodes remain available through those file bind mounts. Confirm a disk is tmpfs-backed with:

```bash
findmnt --target /qemu/builds/packer-jammy-ZFSENC-<timestamp>-<pid>/packer-jammy-ZFSENC-<timestamp>-<pid>.raw
```

Raw disks are ephemeral. `run-packer.sh` prints the exact cleanup commands. Stop QEMU first, then unmount each final raw-file bind mount and remove its final build directory as instructed. RAM-backed builds are not integrated into CI yet.

## Configuration and ISO layout

`--set KEY=VALUE` overrides the selected config file and Packer defaults:

```bash
./run-packer.sh --ubuntu-version 24.04.2 --discenc NOENC --disk-size 5G \
  --set MYHOSTNAME=testbox --set POOLNAME=testpool
```

For remote access, `--set SSHPUBKEY='...'` installs a public key; it is also used for Dropbear in encrypted builds.

ISOs are downloaded automatically from releases.ubuntu.com, or you can point to a local cache. Keep local ISOs in release-named directories and pass `--iso-src file:///qemu/ISOs`:

```text
/qemu/ISOs/jammy/ubuntu-22.04.5-live-server-amd64.iso
/qemu/ISOs/noble/ubuntu-24.04.2-live-server-amd64.iso
/qemu/ISOs/resolute/ubuntu-26.04-live-server-amd64.iso
```

### Packer Configuration Files

> <dl>
>   <dt>ZFS-root_local.pkr.hcl
>   <dd>Main packer template.  Defines QEMU VM settings, provisioners, and post-processors.
>   <dt>ZFS-root_local.vars.hcl
>   <dd>Default variable overrides.  Edit this to change output paths, ISO sources, or disk defaults.
>   <dt>ZFS-root.conf.packerci
>   <dd>Pre-seed config for ZFS-root.sh.  Sets up packer-friendly defaults (user, encryption, ZFSBootMenu options).
> </dl>

## Build output

Every build has a timestamped `packer-*` directory under `/qemu/builds`. Default builds contain QCOW2 disk files (additional disks have numbered suffixes). RAM builds instead expose tmpfs-backed `.raw` disk files at the same final directory level.

Common artifacts include `efivars.fd`, `build-metadata.txt` (used by `run-kvm.sh`), `build.log`, `manifest.json`, `ZFS-root_final.conf`, and checksums. `packer-output.log` is the wrapper's captured Packer/Docker command output; in RAM mode it is copied out of staging during promotion.

## Running images

`run-kvm.sh` accepts a build directory and reads its metadata. It launches RAM-mode raw disks when their metadata is present, and retains legacy QCOW2 discovery for ordinary builds.

Options:

| Option | Description |
|--------|-------------|
| `--bios` | Force legacy BIOS mode (no UEFI) |
| `--secureboot` | Force SecureBoot (overrides auto-detect) |
| `--ram SIZE` | RAM in MB (default: 2048) |
| `--ssh PORT` | SSH forwarding port - default: 3222 (NAT'd to 22) |
| `--dropbear PORT` | SSH forwarding port for Dropbear - default: 1222 (NAT'd to 222)<br>NOTE: **requires** an ssh key defined |

```bash
./run-kvm.sh [--bios] [--secureboot] [--ram 4096] [--ssh 3222] [--dropbear 1222] \
  /qemu/builds/packer-noble-NOENC-<timestamp>
```

SecureBoot is auto-detected from metadata or EFI variables unless overridden. SSH forwards to port `3222` by default; Dropbear uses `1222`. Docker-created artifacts can be root-owned; You may need a `sudo chown -R ${USER}:${USER} /qemu/builds/packer-<.....>`

SSH into Dropbear on an encrypted booting VM with: (NOTE: Dropbear *requires* ssh key, no user/password)

```
# Use your default ssh keys or specify which key to use
ssh -p 1222 [-i path/to/key] root@localhost
```

SSH into the running VM with:

```
ssh -p 3222 packer@localhost -o PubkeyAuthentication=no
```

## Build Output

Each build creates a timestamped directory under the output prefix (default `/qemu/builds/`):

```
packer-noble-NOENC-2026-02-08-1234/
├── packer-noble-NOENC-2026-02-08-1234.qcow2    # Primary disk
├── packer-noble-NOENC-2026-02-08-1234.qcow2-1  # Additional disk (if multi-disk)
├── efivars.fd                                   # UEFI variables
├── build-metadata.txt                           # Build settings for run-kvm.sh
├── build.log                                    # ZFS-root.sh installation log
├── packer-output.log                            # Full log from `packer build ...` command
├── manifest.json                                # Packer manifest
├── ZFS-root_final.conf                          # Final ZFS-root.conf used for build
└── *.sha256.checksum                            # Disk checksums
```
