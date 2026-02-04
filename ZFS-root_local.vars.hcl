
#
# For running packer locally
#

# When running under docker this location is relative to the container environment
# So the outside/host location must be bind-mounted into the container at this location
# eg.  -v "/home/location/VirtualBox:/VirtualBox"
output_prefix       = "/VirtualBox/qemu/"

# false -> we can see the VM console gui
# true  -> console is hidden
# headless            = false

ubuntu_version      = "24.04.2"
ubuntu_live_iso_src = "file:///VirtualBox/ISOs"

# Default to one 10G disk
disk_size           = "10G"
additional_disks    = []  # empty for single disk
# additional_disks  = ["10G"]  # for two total disks (one primary + one additional etc.)
# For 3x disks total via cmdline  you can call packer with   packer build -var 'additional_disks=["10G","10G"]' ...
