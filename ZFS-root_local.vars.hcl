
#
# For running packer locally
#

# When running under docker this location is relative to the container environment
# So the outside/host location must be bind-mounted into the container at this location
# eg.  -v "/home/location/VirtualBox:/VirtualBox"
output_prefix       = "/VirtualBox/qemu/"

# false -> we can see the VM console gui
# true  -> console is hidden
headless            = true

ubuntu_version      = "24.04.2"
ubuntu_live_iso_src = "file:///home/deano/VirtualBox/ISOs"
