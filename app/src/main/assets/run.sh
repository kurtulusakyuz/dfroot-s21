#!/system/bin/sh
echo /sbin/modprobe > /proc/sys/kernel/modprobe
echo core > /proc/sys/kernel/core_pattern
touch /dev/dfm0
