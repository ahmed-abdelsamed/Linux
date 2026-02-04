Here's a comprehensive guide to optimize Rocky Linux 9 for high performance:

## 🚀 **System-Level Optimizations**

### **1. Update System & Enable Repositories**
```bash
# Update everything
sudo dnf update -y

# Enable CRB (CodeReady Builder) and EPEL
sudo dnf config-manager --set-enabled crb
sudo dnf install -y epel-release

# Install performance tools
sudo dnf install -y tuned tuned-utils tuned-profiles-cpu-partitioning \
  kernel-tools numactl hwloc iperf3 sysstat bpftool
```

### **2. Configure Tuned Profile**
```bash
# List available profiles
sudo tuned-adm list

# Apply high-performance profile
sudo tuned-adm profile throughput-performance

# For latency-sensitive workloads (databases, real-time)
sudo tuned-adm profile latency-performance

# For virtual machines
sudo tuned-adm profile virtual-guest

# Create custom profile
sudo mkdir /etc/tuned/my-perf-profile
sudo tee /etc/tuned/my-perf-profile/tuned.conf << 'EOF'
[main]
summary=Custom High Performance Profile

[cpu]
governor=performance
energy_perf_bias=performance
min_perf_pct=100

[vm]
transparent_hugepages=always
dirty_ratio=10
dirty_background_ratio=5

[sysctl]
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 300000
net.core.somaxconn = 1024
kernel.sched_min_granularity_ns = 10000000
kernel.sched_wakeup_granularity_ns = 15000000
EOF

sudo tuned-adm profile my-perf-profile
```

## ⚡ **CPU & Process Optimizations**

### **3. CPU Governor & Frequency**
```bash
# Check current governor
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Set to performance (prevents CPU from downclocking)
sudo tee /etc/systemd/system/cpu-performance.service << 'EOF'
[Unit]
Description=Set CPU governor to performance
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now cpu-performance.service

# Disable CPU frequency scaling entirely
sudo dnf install -y cpupower
sudo cpupower frequency-set -g performance
sudo cpupower idle-set -D 2  # Disable deep C-states
```

### **4. Process Scheduling & Priority**
```bash
# Install real-time kernel (for latency-sensitive apps)
sudo dnf install -y kernel-rt kernel-rt-core kernel-rt-modules

# Set real-time priority for critical processes
sudo tee -a /etc/security/limits.conf << 'EOF'
@criticalusers - rtprio 99
@criticalusers - memlock unlimited
@criticalusers - nice -20
EOF

# Optimize process limits
sudo tee -a /etc/sysctl.d/99-perf.conf << 'EOF'
kernel.sched_autogroup_enabled = 0
kernel.sched_min_granularity_ns = 10000000
kernel.sched_wakeup_granularity_ns = 15000000
kernel.sched_migration_cost_ns = 5000000
kernel.sched_nr_migrate = 32
EOF
```

## 💾 **Memory & HugePages Optimization**

### **5. Transparent HugePages**
```bash
# Enable THP (for memory-intensive workloads)
sudo tee /etc/systemd/system/hugepages.service << 'EOF'
[Unit]
Description=Enable Transparent HugePages
Before=sysinit.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "echo always > /sys/kernel/mm/transparent_hugepage/enabled"
ExecStart=/bin/bash -c "echo defer+madvise > /sys/kernel/mm/transparent_hugepage/defrag"
ExecStart=/bin/bash -c "echo 0 > /sys/kernel/mm/transparent_hugepage/khugepaged/scan_sleep_millisecs"
RemainAfterExit=true

[Install]
WantedBy=sysinit.target
EOF

sudo systemctl enable --now hugepages.service

# For databases (disable THP, use explicit hugepages)
sudo tee -a /etc/sysctl.d/99-hugepages.conf << 'EOF'
vm.nr_hugepages = 1024  # Adjust based on your RAM (2MB each)
vm.hugetlb_shm_group = 0
vm.swappiness = 10
vm.vfs_cache_pressure = 50
EOF
```

### **6. NUMA Optimization**
```bash
# Check NUMA topology
numactl --hardware

# Install numad for automatic NUMA balancing
sudo dnf install -y numad
sudo systemctl enable --now numad

# Optimize NUMA policy
sudo tee -a /etc/sysctl.d/99-numa.conf << 'EOF'
vm.zone_reclaim_mode = 0
vm.numa_zonelist_order = node
EOF

# Run process with NUMA affinity
numactl --cpunodebind=0 --membind=0 <your-application>
```

## 🌐 **Network Performance**

### **7. Network Stack Tuning**
```bash
# Network optimizations
sudo tee /etc/sysctl.d/99-network-perf.conf << 'EOF'
# Socket buffers
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# TCP tuning
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_mem = 8388608 12582912 16777216

# TCP congestion control (BBR is best for high-speed networks)
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Connection tracking
net.netfilter.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_tcp_timeout_established = 86400

# Network device backlogs
net.core.netdev_max_backlog = 300000
net.core.somaxconn = 1024
net.ipv4.tcp_max_syn_backlog = 2048

# Timestamps and window scaling
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
EOF

# Apply changes
sudo sysctl -p /etc/sysctl.d/99-network-perf.conf

# Install and configure irqbalance
sudo dnf install -y irqbalance
sudo systemctl enable --now irqbalance

# Set IRQ affinity (for specific NICs)
sudo tee /etc/systemd/system/irq-affinity.service << 'EOF'
[Unit]
Description=Set IRQ affinity
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "for irq in \$(grep eth0 /proc/interrupts | cut -d: -f1); do echo 1 > /proc/irq/\$irq/smp_affinity; done"
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF
```

### **8. NIC Tuning**
```bash
# Install ethtool
sudo dnf install -y ethtool

# Optimize NIC settings (adjust eth0 to your interface)
sudo ethtool -G eth0 rx 4096 tx 4096
sudo ethtool -K eth0 gro on gso on tso on
sudo ethtool -C eth0 rx-usecs 10 tx-usecs 10

# Jumbo frames (if network supports)
sudo ip link set eth0 mtu 9000

# Disable offloading if causing issues
sudo ethtool -K eth0 gro off gso off tso off
```

## 💿 **Storage & I/O Optimization**

### **9. Filesystem & Mount Options**
```bash
# Check current mounts
mount | grep -E "(ext4|xfs|btrfs)"

# Optimize mount options in /etc/fstab
# XFS (recommended for performance):
/dev/sdb1 /data xfs defaults,noatime,nodiratime,nobarrier,allocsize=256m,logbufs=8,logbsize=256k 0 2

# EXT4:
/dev/sdc1 /app ext4 defaults,noatime,nodiratime,nobarrier,data=writeback,discard 0 2

# BTRFS:
/dev/sdd1 /storage btrfs defaults,noatime,compress=zstd:3,space_cache=v2,autodefrag 0 2

# Remount with new options
sudo mount -o remount /data
```

### **10. I/O Scheduler & Queue Depth**
```bash
# Check current scheduler
cat /sys/block/sda/queue/scheduler

# Set to none for NVMe, kyber for SSDs, mq-deadline for HDDs
sudo tee /etc/udev/rules.d/60-ioscheduler.rules << 'EOF'
# NVMe SSD
ACTION=="add|change", KERNEL=="nvme[0-9]n[0-9]", ATTR{queue/scheduler}="none"

# SATA SSD
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="kyber"

# HDD
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="1", ATTR{queue/scheduler}="mq-deadline"
EOF

# Increase queue depth for NVMe
sudo tee -a /etc/modprobe.d/nvme.conf << 'EOF'
options nvme poll_queues=4
options nvme io_timeout=30
EOF

# Update initramfs
sudo dracut -f
```

### **11. Direct I/O & Async I/O**
```bash
# Increase aio-max-nr (for databases)
sudo tee -a /etc/sysctl.d/99-aio.conf << 'EOF'
fs.aio-max-nr = 1048576
fs.file-max = 2097152
EOF

# Install libaio
sudo dnf install -y libaio

# Test with fio
sudo dnf install -y fio
fio --name=test --ioengine=libaio --rw=randread --bs=4k --numjobs=4 --size=1G --runtime=60 --group_reporting
```

## 🔧 **Kernel Tuning**

### **12. Kernel Parameters**
```bash
# Complete performance kernel tuning
sudo tee /etc/sysctl.d/99-kernel-perf.conf << 'EOF'
# VM settings
vm.swappiness = 10
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10
vm.dirty_expire_centisecs = 3000
vm.dirty_writeback_centisecs = 500

# PID limits
kernel.pid_max = 4194304
kernel.threads-max = 524288

# File handles
fs.file-max = 2097152
fs.nr_open = 2097152

# IPC
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296

# Core dumps
kernel.core_pattern = /var/crash/core.%e.%p.%h.%t
fs.suid_dumpable = 2

# Security-performance tradeoff
kernel.kptr_restrict = 1
kernel.yama.ptrace_scope = 1
EOF

# Apply all sysctl changes
sudo sysctl --system
```

### **13. Disable Unnecessary Services**
```bash
# List all services
systemctl list-unit-files --type=service

# Disable services that consume resources
sudo systemctl disable --now \
  bluetooth \
  cups \
  avahi-daemon \
  ModemManager \
  teamviewerd \
  packagekit \
  NetworkManager-wait-online

# For minimal installation
sudo dnf groupremove -y "Server with GUI"
sudo dnf remove -y \
  gnome* \
  kde* \
  xorg* \
  libreoffice* \
  firefox
```

## 📊 **Monitoring & Verification**

### **14. Install Performance Monitoring Tools**
```bash
# Comprehensive monitoring suite
sudo dnf install -y \
  atop \
  htop \
  iotop \
  iftop \
  nethogs \
  powertop \
  perf \
  sysstat \
  nmon \
  glances \
  bpftrace

# Enable sysstat data collection
sudo systemctl enable --now sysstat

# View performance metrics
sar -u 1 3      # CPU
sar -r 1 3      # Memory  
sar -b 1 3      # I/O
sar -n DEV 1 3  # Network
```

### **15. Benchmark Your System**
```bash
# CPU benchmark
sudo dnf install -y stress-ng
stress-ng --cpu 0 --cpu-method matrixprod --metrics-brief -t 30

# Memory benchmark
stress-ng --vm 4 --vm-bytes 4G --vm-method all -t 30

# Disk benchmark
fio --name=randwrite --ioengine=libaio --iodepth=32 \
  --rw=randwrite --bs=4k --direct=1 --size=1G --numjobs=4 \
  --runtime=60 --group_reporting

# Network benchmark
iperf3 -s &  # On server
iperf3 -c <server-ip> -t 30 -P 8
```

## 🎯 **Application-Specific Optimizations**

### **For Databases (PostgreSQL/MySQL):**
```bash
# Install and configure hugepages
sudo dnf install -y libhugetlbfs-utils
hugeadm --pool-pages-min=2MB:1024

# Configure shared memory
sudo tee -a /etc/sysctl.d/99-db.conf << 'EOF'
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
kernel.shm_rmid_forced = 1
EOF
```

### **For Web Servers (Nginx/Apache):**
```bash
# Increase file descriptors
sudo tee -a /etc/security/limits.d/nginx.conf << 'EOF'
nginx soft nofile 65535
nginx hard nofile 65535
nginx soft nproc 65535
nginx hard nproc 65535
EOF
```

### **For Kubernetes/Docker:**
```bash
# Optimize container runtime
sudo tee -a /etc/sysctl.d/99-containerd.conf << 'EOF'
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF

# Use overlay2 with xfs
sudo mkfs.xfs -f /dev/sdx
echo "/dev/sdx /var/lib/docker xfs defaults,pquota 0 0" | sudo tee -a /etc/fstab
```

## 🚀 **Quick Optimization Script**

Create and run this comprehensive optimization script:

```bash
#!/bin/bash
# rocky9-perf-optimize.sh

set -e

echo "🔧 Rocky Linux 9 High Performance Optimization"
echo "============================================="

# 1. System updates
echo "1. Updating system..."
sudo dnf update -y
sudo dnf config-manager --set-enabled crb
sudo dnf install -y epel-release

# 2. Install performance tools
echo "2. Installing performance tools..."
sudo dnf install -y tuned tuned-utils kernel-tools numactl hwloc \
  irqbalance ethtool fio stress-ng sysstat bpftool cpupower

# 3. Apply tuned profile
echo "3. Applying tuned profile..."
sudo tuned-adm profile throughput-performance

# 4. CPU optimizations
echo "4. Optimizing CPU..."
sudo cpupower frequency-set -g performance
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# 5. Network optimizations
echo "5. Optimizing network..."
sudo tee /etc/sysctl.d/99-network-perf.conf << 'EOF'
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 300000
net.core.somaxconn = 1024
net.ipv4.tcp_congestion_control = bbr
EOF

# 6. Memory optimizations
echo "6. Optimizing memory..."
sudo tee /etc/sysctl.d/99-memory-perf.conf << 'EOF'
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10
EOF

# 7. Apply all changes
echo "7. Applying kernel parameters..."
sudo sysctl --system

# 8. Disable unnecessary services
echo "8. Disabling unnecessary services..."
sudo systemctl disable --now bluetooth cups avahi-daemon ModemManager

# 9. Create monitoring script
echo "9. Setting up monitoring..."
sudo tee /usr/local/bin/check-perf << 'EOF'
#!/bin/bash
echo "=== Performance Status ==="
echo "CPU Governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
echo "Tuned Profile: $(tuned-adm active)"
echo "Memory: $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
echo "Load: $(uptime)"
echo "=========================="
EOF
sudo chmod +x /usr/local/bin/check-perf

echo "✅ Optimization complete! Reboot for full effect."
echo "Run 'check-perf' to verify optimizations."
```

## 📊 **Verification Commands**

After applying optimizations:

```bash
# Verify CPU
cpupower frequency-info

# Verify tuned profile
tuned-adm active

# Verify sysctl settings
sysctl -a | grep -E "(tcp|net.core|vm)"

# Check hugepages
cat /proc/meminfo | grep Huge

# Monitor performance
check-perf
```

These optimizations will significantly boost performance for **servers, databases, high-traffic web applications, and compute-intensive workloads** on Rocky Linux 9. Adjust parameters based on your specific workload characteristics.