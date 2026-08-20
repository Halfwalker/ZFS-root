#
# For running packer locally
# Defaults shown commented out
#

# false -> we can see the VM console gui
# true  -> console is hidden
# headless              = true

# Default for display is "sdl" - this is how one can set it to "gtk" or "none"
#   gtk :  uses GTK to render the virtual machine window
#   sdl :  Alternative backend; uses SDL2 to render the display. Useful if GTK
#          fails or if hardware acceleration (like gl=on) behaves better with
#          SDL on your graphics driver.
#   none : Passes no -display flag to QEMU, letting QEMU fall back to system
#          defaults or headless/VNC execution
# display               = "gtk"

# When running under docker this location is relative to the container environment
# So the outside/host location must be bind-mounted into the container at this location
# eg.  -v "/home/location/somewhere:/qemu/builds"
# No default - must be set
output_prefix         = "/qemu/builds/"

# Which Ubuntu version to install
# ubuntu_version        = "24.04.2"
# ubuntu_version_name   = "noble"

# Disk encryption - NOENC, ZFS (zfs native), LUKS
# discenc               = "NOENC"

# Where to find ISOs - this can be local with "file:///some/dir"
# For local ISOs, each ISO should be in the appropriate release-named dir
#   /qemu/ISOs/resolute/ubuntu-26.04-live-server-amd64.iso
#   /qemu/ISOs/questing/ubuntu-25.10-live-server-amd64.iso
#   /qemu/ISOs/plucky/ubuntu-25.04-live-server-amd64.iso
#   /qemu/ISOs/noble/ubuntu-24.04.2-live-server-amd64.iso
#   /qemu/ISOs/jammy/ubuntu-22.04.5-live-server-amd64.iso
#   /qemu/ISOs/focal/ubuntu-20.04.5-live-server-amd64.iso
# ubuntu_live_iso_src   = "https://releases.ubuntu.com"
ubuntu_live_iso_src   = "file:///qemu/ISOs"

# Disk dize - default to one 5G disk
# disk_size             = "5G"

# Multiple disks - how many extra to build
# additional_disks      = []  # default empty for single primary disk
# additional_disks      = ["5G"]  # for two total disks (one primary + one additional etc.)
# For 3x disks total via cmdline  you can call packer with   packer build -var 'additional_disks=["5G","5G"]' ...

# Raid level if more than 1 disk
# If not set explicitly defaults to NO raid, so disks are individual vdevs with no redundancy
# mirror s only option for 2 disks
# mirror or raidz1 for 3+ disks
# raidlevel             = ""

# Main config file for ZFS-root.sh
# config_file           = "ZFS-root.conf.packerci"

