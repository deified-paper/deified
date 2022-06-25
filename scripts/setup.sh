#!/bin/sh

set -e

# packages
apt-get update
apt-get install -y build-essential binutils-dev cmake ccache ninja-build linux-headers-$(uname -r) clang-11 clang-format-11 llvm-11-dev linux-tools-$(uname -r) libncurses-dev libssl-dev libtinfo-dev wget

# perf
echo "kernel.perf_event_paranoid = -1\nkernel.kptr_restrict = 0" | tee -a /etc/sysctl.conf
sysctl -f

# kernel interface
echo "\ndebugfs\t/sys/kernel/debug\tdebugfs\tdefaults,mode=755\t0\t0\ntracefs\t/sys/kernel/debug/tracing\ttracefs\tdefaults,mode=755\t0\t0" | tee -a /etc/fstab

# hugepages
sed -i "s/^GRUB_CMDLINE_LINUX=\"/&hugepagesz=2MB hugepages=8192 /" /etc/default/grub
update-grub
mkdir /mnt/huge_1GB
chmod a+rw -R /mnt/huge_1GB
mkdir /mnt/huge_2MB
chmod a+rw -R /mnt/huge_2MB
echo "\nnodev\t/mnt/huge_1GB\thugetlbfs\tpagesize=1GB\t0\t0\nnodev\t/mnt/huge_2MB\thugetlbfs\tpagesize=2MB\t0\t0" | tee -a /etc/fstab
