 _     _
| |   (_)_ __  _   ___  __
| |   | | '_ \| | | \ \/ /
| |___| | | | | |_| |>  <
|_____|_|_| |_|\__,_/_/\_\

----------------------------------------------------
### Web Sites
'
https://www.lazysystemadmin.com/
https://yallalabs.com/


========================================================================

#ERROR: can not find RHNS CA file: /usr/share/rhn/RHN-ORG-TRUSTED-SSL-CERT
# yum install httpd
Loaded plugins: product-id, rhnplugin, search-disabled-repos, subscription-manager


ERROR: can not find RHNS CA file: /usr/share/rhn/RHN-ORG-TRUSTED-SSL-CERT


#Resolution
Set enabled parameter to 0 for disabling the rhnplugin.

/etc/yum/pluginconf.d/rhnplugin.conf 
[main]
enabled = 0              <==
gpgcheck = 1
minrate=1
timeout=300

2) Enable rhnplugin.

# sed -ie 's/^enabled = 0/enabled = 1/g' /etc/yum/pluginconf.d/rhnplugin.conf
# yum install httpd
Loaded plugins: product-id, rhnplugin, search-disabled-repos, subscription-manager

ERROR: can not find RHNS CA file: /usr/share/rhn/RHN-ORG-TRUSTED-SSL-CERT

4) Disable rhnplugin.
# sed -ie 's/^enabled = 1/enabled = 0/g' /etc/yum/pluginconf.d/rhnplugin.conf
5) Run yum command.
# yum install httpd
Loaded plugins: product-id, search-disabled-repos, subscription-manager
Resolving Dependencies
-----------------------------------------------------
## Openssl version:
 openssl version -a

### SSL TLS Version:
[root@IFRS9-db ~]# openssl ciphers -v | awk '{print $2}' | sort | uniq
SSLv3
TLSv1.2
'
### Create password encrypt by openssl
$ sudo openssl passwd -1 > cloud-config-file

=======================================================================================
## How to use yum to download a package without installing it
Resolution
There are two ways to download a package without installing it.

One is using the "downloadonly" plugin for yum, the other is using "yumdownloader" utility.

Downloadonly plugin for yum
1- Install the package including "downloadonly" plugin:


(RHEL5)
# yum install yum-downloadonly

(RHEL6)
# yum install yum-plugin-downloadonly

2- Run yum command with "--downloadonly" option as follows:

# yum install --downloadonly --downloaddir=<directory> <package>
Confirm the RPM files are available in the specified download directory.

----------
Note:

1- Before using the plugin, check /etc/yum/pluginconf.d/downloadonly.conf to confirm that this plugin is "enabled=1"
2- This is applicable for "yum install/yum update" and not for "yum groupinstall". Use "yum groupinfo" to identify packages within a specific group.
3- If only the package name is specified, the latest available package is downloaded (such as sshd). Otherwise, you can specify the full package name and version (such as httpd-2.2.3-22.el5).
4- If you do not use the --downloaddir option, files are saved by default in /var/cache/yum/ in rhel-{arch}-channel/packages
5- If desired, you can download multiple packages on the same command.
6- You still need to re-download the repodata if the repodata expires before you re-use the cache. By default it takes two hours to expire.
-----

## Yumdownloader
If downloading a installed package, "yumdownloader" is useful.

1- Install the yum-utils package:
# yum install yum-utils

2- Run the command followed by the desired package:

# yumdownloader <package>

Note:

1- The package is saved in the current working directly by default; use the --destdir option to specify an alternate location.
2- Be sure to add --resolve if you need to download dependencies.

-----------------------------------------
##Downloading RPM Packages with dependencies [ yumdownloader Vs yum-downloadonly Vs repoquery]
root@app-1 # yum deplist cups
'
Finding dependencies: 
package: cups.ppc 2.2.3-3
  dependency: /bin/sh
   Unsatisfied dependency
  dependency: cups-libs = 2.2.3-3
   provider: cups-libs.ppc 2.2.3-3
  dependency: dbus >= 1.10.14-1
   provider: dbus.ppc 1.12.16-1
  dependency: libC.a(ansi_32.o)
   Unsatisfied dependency
  dependency: libC.a(shr.o)
   Unsatisfied dependency
  dependency: libc.a(shr.o)
   Unsatisfied dependency
  dependency: libcups.a(libcups.so.2)
   provider: cups-libs.ppc 2.2.3-3
  dependency: libcupscgi.a(libcupscgi.so.1)
   provider: cups-libs.ppc 2.2.3-3
  dependency: libcupsimage.a(libcupsimage.so.2)
   provider: cups-libs.ppc 2.2.3-3
  dependency: libcupsmime.a(libcupsmime.so.1)
   provider: cups-libs.ppc 2.2.3-3
  dependency: libcupsppdc.a(libcupsppdc.so.1)
   provider: cups-libs.ppc 2.2.3-3
  dependency: libdbus-1.a(libdbus-1.so.3)
   provider: dbus.ppc 1.12.16-1
  dependency: libpam.a(shr.o)
   Unsatisfied dependency
  dependency: libpthreads.a(shr_xpg5.o)
   Unsatisfied dependency
 '
1- ### Install yumdownloader 
 # yum install yum-utils

For example, to download the RPM “firefox” and all its dependencies, use the beow command.

# yumdownloader --destdir=/var/tmp/ --resolve firefox

Here,
–destdir is the directory where you want the RPM packages to be saved to (defaults to current directory if not specified).
–resolve – resolves dependencies and download required packages

yumdownloader program is quite powerful tool to download packages when used with appropriate wildcards. For example:

# yumdownloader [a]*                (will download all available packages whose name starts with "a")
# yumdownloader [a-c]*              (will download all available packages whose name starts with "a", "b" and "c")
# yumdownloader glibc*              (will download all available packages whose name starts with "glibc")

Note
:
– The package is saved in the current working directly by default; use the –destdir option to specify an alternate location.
– Be sure to add –resolve if you need to download dependencies.

2. ###  repoquery / repotrack
Frequently used “yumdownloader –resolve” command to download the package along with its dependencies does not always successfully recognize all dependencies. It is better to use “repoquery” to find the dependencies and then use “yumdownloader” to download them.

For example you can use the repoquery command to find all the dependencies for the firefox RPM and then use the command output with “yumdownloader” for downloading the dependencies.

# repoquery -R --resolve --recursive firefox | xargs -r yumdownloader
You can also use the “repotrack” utility to download the RPM along with all its dependencies. For Example:

# repotrack firefox

3. ### yum-downloadonly plugin for yum
The “yum-downloadonly” plugin allows “yum” to download packages without installing them. Install the package including “downloadonly” plugin:

(CentOS/RHEL 5)
# yum install yum-downloadonly

(CentOS/RHEL 6,7)
# yum install yum-plugin-downloadonly
Run yum command with “–downloadonly” option as follows:

# yum install --downloadonly --downloaddir=[directory] [package]

Notes about yum-downloadonly plugin
– Before using the plugin, check /etc/yum/pluginconf.d/downloadonly.conf to confirm that this plugin is “enabled=1”
– This is applicable for “yum install/yum update” and not for “yum groupinstall”. Use “yum groupinfo” to identify packages within a specific group.
– If only the package name is specified, the latest available package is downloaded (such as sshd). Otherwise, you can specify the full package name and version (such as httpd-2.2.3-22.el5).
– If desired, you can download multiple packages on the same command.
– You still need to re-download the repodata if the repodata expires before you re-use the cache. By default it takes two hours to expire.


'
sudo dnf download --resolve nano


============================================================================================
## How to Boot into Single User Mode in CentOS/RHEL 7
ro to rw init=/sysroot/bin/sh

press Ctrl-X or F10

# chroot /sysroot/

# reboot -f

===============================================
=========================================================
## in launcher GUI appear unknow characters:
 # Solved:
 yum install -y dejavu-sans-fonts
 $ fc-list
 'list all fonts in linux'

'
=====================================================
## How to clone linux rootvg:
$ cat /proc/partitions/
$ sudo dd bs=4M conv=sync,noerror status=progress if=/dev/sda of=/dev/sdd

==========================================================
## proxy configuration:
export http_proxy="http://sas.wacthlist:asd1010%40@172.17.0.25:8080/"
export https_proxy="https://sas.wacthlist:asd1010%40@172.17.0.25:8080/"

===========================================================================
### remove all except files
[root@T24BKP Dec2018]#  shopt -s extglob
[root@T24BKP Dec2018]# rm -fv   !("AML16.31Dec18.234500.aml.tar.gz")

=============================================================================
## Change hostname:
$ nmtui-hostname

hostname on centos 6
[root@HDBa1 ~]# vim /etc/sysconfig/network

========================================================
# Set Static IP Address in CentOS 8
nmtui-edit
nmtui-connect
# ethtool enp0s3
# mii-tool enp0s3

## List all services status
[root@automation ~]#  systemctl list-unit-files -t service
UNIT FILE                                  STATE   
arp-ethers.service                         disabled
atd.service                                enabled 
auditd.service                             enabled 
autovt@.service                            enabled 
blk-availability.service                   disabled
chrony-dnssrv@.service                     static  
chrony-wait.service                        disabled
chronyd.service                            enabled 
clean-mount-point@.service                 static  
cockpit-motd.service                       static  
cockpit.service                            static  
console-getty.service                      disabled
container-getty@.service                   static  
cpupower.service                           disabled
crond.service                              enabled 
dbus-org.fedoraproject.FirewallD1.service  enabled 
dbus-org.freedesktop.hostname1.service     static  
dbus-org.freedesktop.locale1.service       static  
dbus-org.freedesktop.login1.service        static  
dbus-org.freedesktop.nm-dispatcher.service enabled 
dbus-org.freedesktop.portable1.service     static  
dbus-org.freedesktop.resolve1.service      enabled 
dbus-org.freedesktop.timedate1.service     enabled 
lines 1-24
=======================================================
vi /etc/NetworkManager/system-connections/ens18.nmconnection
[connection]
id=ens18
uuid=3aff56e5-0e35-3a94-b8c5-3f942ca3d084
type=ethernet
autoconnect-priority=-999
interface-name=ens18
timestamp=1762339958

[ethernet]

[ipv4]
address1=192.168.100.40/24,192.168.100.1
dns=192.168.100.200;8.8.8.8;1.1.1.1;
dns-search=linkdev.local;
method=manual

[ipv6]
addr-gen-mode=eui64
method=disabled

[proxy]


===================================
[root@automation ~]# pstree -p
systemd(1)─┬─NetworkManager(7110)─┬─{NetworkManager}(7113)
           │                      └─{NetworkManager}(7114)
           ├─VGAuthService(25132)
           ├─atd(1770)
           ├─auditd(1583)─┬─sedispatch(1585)
           │              ├─{auditd}(1584)
           │              └─{auditd}(1586)
           ├─chronyd(1636)
           ├─crond(6043)
           ├─dbus-daemon(1615)───{dbus-daemon}(1643)
           ├─firewalld(17971)───{firewalld}(18189)
           ├─irqbalance(1628)───{irqbalance}(1645)
           ├─login(1773)───bash(5818)

==========================================================
## Paralle SSH:
$ pip install pssh
$ pssh -H 'test@192.168.0.102' date

==================================================
###  File Descriptor Requirements (Linux Systems)
'To Increase the File Descriptor Limit (Linux) Display the current hard limit of your machine.
The hard limit is the maximum server limit that can be set without tuning the kernel parameters in proc file system.
'


$ ulimit -aH
core file size (blocks)       unlimited
data seg size (kbytes)        unlimited
file size (blocks)            unlimited
max locked memory (kbytes)    unlimited
max memory size (kbytes)      unlimited
open files                    1024
pipe size (512 bytes)         8
stack size (kbytes)           unlimited
cpu time (seconds)            unlimited
max user processes            4094
virtual memory (kbytes)       unlimited

## Edit the /etc/security/limits.conf and add the lines:
     soft   nofile  1024
     hard   nofile  65535 

Edit the /etc/pam.d/login by adding the line:
session required /lib/security/pam_limits.so
Use the system file limit to increase the file descriptor limit to 65535.
The system file limit is set in /proc/sys/fs/file-max .

$ echo 65535 > /proc/sys/fs/file-max
Use the ulimit command to set the file descriptor limit to the hard limit specified in /etc/security/limits.conf.
$ulimit -n unlimited
Restart your system.

=================================================================
resolvectl status
systemd-resolve --status
journalctl -u systemd-resolved -f
sudo systemctl edit systemd-resolved
sudo systemctl restart systemd-resolved
rm systemd-resolved
shutdown -r 0
sudo !! https://t.co/kRFs6W7i0S

=============================================
### curl
curl -k https://whatever.com/script.php

==============================================
### Disable IPV6
Post describes procedure to disable IPv6 on CentOS/RHEL 7. There are 2 ways to do this :
1. Disable IPv6 in kernel module (requires reboot)
2. Disable IPv6 using sysctl settings (no reboot required)

To verify if IPv6 is enabled or not, execute :

# ifconfig -a | grep inet6
        inet6 fe80::211:aff:fe6a:9de4  prefixlen 64  scopeid 0x20
        inet6 ::1  prefixlen 128  scopeid 0x10[host]
1. Disable IPv6 in kernel module (requires reboot)
1. Edit /etc/default/grub and add ipv6.disable=1 in line GRUB_CMDLINE_LINUX, e.g.:

# cat /etc/default/grub
GRUB_TIMEOUT=5
GRUB_DEFAULT=saved
GRUB_DISABLE_SUBMENU=true
GRUB_TERMINAL_OUTPUT="console"
GRUB_CMDLINE_LINUX="ipv6.disable=1 crashkernel=auto rhgb quiet"
GRUB_DISABLE_RECOVERY="true"
2. Regenerate a GRUB configuration file and overwrite existing one:

# grub2-mkconfig -o /boot/grub2/grub.cfg

3. Restart system and verify no line “inet6” in “ip addr show” command output.

# shutdown -r now
# ip addr show | grep net6


2. Disable IPv6 using sysctl settings (no reboot required)
1. Append below lines in /etc/sysctl.conf:

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
NOTE : To disable IPv6 on a single interface add below lines to /etc/sysctl.conf :
net.ipv6.conf.[interface].disable_ipv6 = 1 ### put interface name here [interface]
net.ipv6.conf.default.disable_ipv6 = 1
2. To make the settings affective, execute :

# sysctl -p
NOTE : make sure the file /etc/ssh/sshd_config contains the line AddressFamily inet to avoid breaking SSH Xforwarding if you are using the sysctl method
3. Add the AddressFamily line to sshd_config :

# vi /etc/ssh/sshd_config
....
AddressFamily inet
....
Restart sshd for changes to get get effect :

# systemctl restart sshd
---------------------------------------------------
## Enable X-Forwarding 

sudo dnf install xorg-x11-xauth xorg-x11-utils xorg-x11-fonts-* xauth
sudo nano /etc/ssh/sshd_config


X11Forwarding yes
X11DisplayOffset 10
X11UseLocalhost yes

sudo systemctl restart sshd

#On the Client:
nano ~/.ssh/config
Host *
    ForwardX11 yes
    ForwardX11Trusted yes


------------------------------------------------------
### enable the CTR or GCM cipher mode  encryption
#SSH vulnerabilities: HMAC algorithms and CBC ciphers

vi /etc/ssh/sshd_config 

# Ciphers and keying
Ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
#RekeyLimit default none



====================================================

rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE} (%{ARCH})\n' libXi
rpm -q libXi 

=============================================================

# How to configure password complexity for all users including root using pam_passwdqc.so & pam_cracklib.so
different between two modules:
passwdqc ---> apply include root 
cracklib ---> apply all users except root 

##  install package

[root@HDB17 home]# rpm -qf /lib64/security/pam_
pam_access.so          pam_limits.so          pam_sss.so
pam_cap.so             pam_listfile.so        pam_stress.so
pam_chroot.so          pam_localuser.so       pam_succeed_if.so
pam_console.so         pam_loginuid.so        pam_systemd.so
pam_cracklib.so        pam_mail.so            pam_tally2.so
pam_debug.so           pam_mkhomedir.so       pam_time.so
pam_deny.so            pam_motd.so            pam_timestamp.so
pam_echo.so            pam_namespace.so       pam_tty_audit.so
pam_env.so             pam_nologin.so         pam_umask.so
pam_exec.so            pam_permit.so          pam_unix_acct.so
pam_faildelay.so       pam_postgresok.so      pam_unix_auth.so
pam_faillock.so        pam_pwhistory.so       pam_unix_passwd.so
pam_filter/            pam_pwquality.so       pam_unix_session.so
pam_filter.so          pam_rhosts.so          pam_unix.so
pam_fprintd.so         pam_rootok.so          pam_userdb.so
pam_ftp.so             pam_securetty.so       pam_warn.so
pam_group.so           pam_selinux_permit.so  pam_wheel.so
pam_issue.so           pam_selinux.so         pam_winbind.so
pam_keyinit.so         pam_sepermit.so        pam_xauth.so
pam_lastlog.so         pam_shells.so          
[root@HDB17 home]# rpm -qf /lib64/security/pam_cracklib.so 
pam-1.1.8-12.el7_1.1.x86_64

-----------------------
# Another way:
In Red Hat Enterprise Linux 7 default configuration file for password complexity 
/etc/security/pwquality.conf .

Requirement 1: Keep history of passwords used

Insert the following in /etc/pam.d/system-auth and /etc/pam.d/password-auth (after pam_pwquality.so line):

password    requisite     pam_pwhistory.so remember=5 use_authtok

2# inser configuration into /etc/security/pwquality.conf

# Requirement 2: minlen = 9 ( Minimum length of a password)
#Insert the following option in /etc/security/pwquality.conf:

minlen = 9       
#NOTE :- The above requirement is minimum acceptable size for the new password. It will include credits(plus one) if not disabled which is the default.

#Requirement 3: dcredit = -1 (Minimum credit for having required digits in password).
dcredit = -1
#Requirement 4: ucredit = -1 ( Minimum credit for having uppercase characters in password )
ucredit = -1
#Requirement 5: lcredit = 1 ( Maximum credit for having lowercase characters in password )
lcredit = -1
#Requirement 6: ocredit = 1 ( Maximum credit for having other characters in password )
ocredit = -1
#NOTE :- The credit value configured for the requirements "3 - 6" are only for the illustration purpose. The credit value can be configured in different ways as per requirement. Below supporting information for configuring the same -

1) Credit Value > 0 : Maximum credit for having respective characters in the new password.
2) Credit Value < 0 : Minimum mandatory credit required for having respective characters in the new password.
3) Credit Value = 0 : No mandatory requirement for having the respective character class in the new password.

#Requirement 7: minclass = 1( Minimum number of required character classes in new password )
minclass = 1

#Requirement 8: maxrepeat = 2 ( Maximum number of allowed consecutive same characters in the new password)
maxrepeat = 2

#Requirement 9: maxclassrepeat = 2 ( Maximum number of allowed consecutive characters of the same class in the new password)
maxclassrepeat = 2

#Requirement 10: A maximum number of characters that is allowed to use in new passwords(compared to old password).
difok = 6

#Requirement 11: Requirement 11. Enforce root for password complexity.
enforce_for_root

#The above examples are for only illustration purpose. For more information refer man page of pwquality.conf.

# man pwquality.conf

====================================================================================
### Create bonds:
/sysconfig/network-scripts/ifcfg-bond0
DEVICE=bond0
BOOTPROTO=none
ONBOOT=yes
IPADDR=172.17.7.182
NETWORK=172.17.7.0
NETMASK=255.255.255.0
GATEWAY=172.17.7.254
USERCTL=no
BONDING_OPTS="mode=0 miimon=200"

=======================================
### /etc/sysconfig/network-scripts/ifcfg-eth0
DEVICE=eth0
MASTER=bond0
SLAVE=yes
USERCTL=no
ONBOOT=yes
BOOTPROTO=none
======================================
### /etc/sysconfig/network-scripts/ifcfg-eth1
DEVICE=eth1
MASTER=bond0
SLAVE=yes
USERCTL=no
ONBOOT=yes
BOOTPROTO=none

=============================================================
============================================================
cat ifcfg-bond0
DEVICE=bond0
TYPE=Ethernet
ONBOOT=yes
USERCTL=no
NM_CONTROLLED=no
MTU=9000
BOOTPROTO=static
IPADDR=172.17.7.181
PREFIX=24
DNS1=172.17.15.35
BONDING_OPTS="mode=802.3ad miimon=100 lacp_rate=fast xmit_hash_policy=layer2+3"


--------------------------------------
cat ifcfg-p5p1
DEVICE=p5p1
BOOTPROTO=none
ONBOOT=yes
SLAVE=yes
USERCTL=no
NM_CONTROLLED=no
MASTER=bond0

-------------------------
cat ifcfg-p5p2
DEVICE=p5p2
BOOTPROTO=none
ONBOOT=yes
SLAVE=yes
USERCTL=no
NM_CONTROLLED=no
MASTER=bond0

=====================================================
====================================================

==========================================
===============================================================================
## Make an rpm package from src.rpm.

    # rpmbuild --rebuild ltfssde-2.4.2.0-[distribution].src.rpm

=====================================================================
## NFS 
172.17.7.81:/home    /backup84   nfs  defaults,_netdev    0   0


===================================================================
### How to delete match word in vim:
:%s/,_netdev//gc

Change each 'foo' to 'bar', but ask for confirmation first.

Press y or n to change or keep your text.
--------------
$ 'cat <<EOT >> ~/.vimrc'
> syntax on
> set nu et ai sts=0 ts=2 sw=2 list hls
> EOT
$ export OC_EDITOR="vim"
$ export KUBE_EDITOR="vim"

========================================================='
## How to check if a library is installed?
ldconfig -p | grep libjpeg

---------------------------------------------
## How to detect hard disk without reboot
echo "- - -" >> /sys/class/scsi_host/host0/scan

ls /sys/class/scsi_host
echo "- - -" > /sys/class/scsi_host/host#/scan
 fdisk -l
 tail -f /var/log/message

---------------------------------------------------
### Clone disk backup and restore:
dd if=/dev/hda of=/dev/hdb bs=1M

## Restore 2 ways:
1- dd if=/dev/hdb of=/dev/hda bs=1M
2- Change grub /etc/grub2.cfg 
:%s/hd0/hd1/g 
reboot 
----------------------------------------------
### Create multi user  with password :
$ sudo vim users.txt 
ahmed:Fr@nkf0rt:1002:1002:Tecmint Admin:/home/ravi:/bin/bash

$sudo chmod 0600 users.txt
OR 
-----------------
`
$ python multiUser.py user_pass.txt
multiUser.py
'
import sys
import os
import string
import random
import crypt
 
# function for create one user with supplied password
def createUser(name,passwd):
   two = ''.join(random.choice(string.ascii_letters) for x in range(2))
   encPass = crypt.crypt(passwd, two)
   os.system("useradd -p "+encPass+ " -m "+name)
 
# main program
if __name__ == '__main__':
   # prepare variables like file name and lists of user and password
   fname = sys.argv[1]
   list_users = []
   list_passwds = []
   # read username and password from file and save to the created lists
   with open(fname,'r') as file:
      for line in file:
         list_temp = line.rstrip('\n').split(" ")
         list_users.append(list_temp[0])
         list_passwds.append(list_temp[1])
   # start creating users
   for i,user in enumerate(list_users):
      createUser(list_users[i],list_passwds[i])
'
user_pass.txt (separate username and password by space)

john 1234
richhat secret123
jackie 1234567
====================================================================
Issue
While mounting AIX nfs shares, the following error is obtained:

Raw
mount.nfs: Remote I/O error

Resolution
Aix NFS server with NFSv4 protocol support
This may be due to a misconfiguration of NFSv4 on the Aix NFS server. For more information, see https://access.redhat.com/solutions/1463043
Aix NFS server without NFSv4 protocol support
To resolve the issue, mount the nfs share with an option vers=3. Eg:

Raw
# mount -o vers=3 server_ip_addr:dir local_mount_point
'
============================================================================
### NFS on Ubuntu 20.04
$sudo apt install nfs-kernel-server
$mkdir /var/nfs/general -p
$sudo chown nobody:nogroup /var/nfs/general

#Configuring the NFS Exports on the Host Server
$sudo nano /etc/exports
'/var/nfs/general    client_ip(rw,sync,no_subtree_check)'

sudo systemctl restart nfs-kernel-server

#Creating Mount Points and Mounting Directories on the Client
$sudo mount host_ip:/var/nfs/general /nfs/general

=========================================================================
### Setup NFS server-client in Centos 7

$yum install nfs-utils
$mkdir /var/nfs_share_dir
$chmod -R 755 /var/nfs_share_dir
$chown nfsnobody:nfsnobody /var/nfs_share_dir

systemctl enable rpcbind
systemctl enable nfs-server
systemctl enable nfs-lock
systemctl enable nfs-idmap
systemctl start rpcbind
systemctl start nfs-server
systemctl start nfs-lock
systemctl start nfs-idmap

$vi /etc/exports
'/var/nfs_share_dir    192.168.48.101(rw,sync,no_root_squash)'
$systemctl restart nfs-server

firewall-cmd --permanent --zone=public --add-service=nfs
firewall-cmd --permanent --zone=public --add-service=mountd
firewall-cmd --permanent --zone=public --add-service=rpc-bind
firewall-cmd --reload

$exportfs -rav 
$exportfs -v 

------------------------
###  Setup NFS-Client(s)

yum install nfs-utils
mkdir -p /mnt/nfs/var/nfs_share_dir

mount -t nfs 192.168.48.100:/var/nfs_share_dir /mnt/nfs/var/nfs_share_dir

-t  type of filesystem
192.168.48.100 server's IP'

### Mounting permanently.
in /etc/fstab 
'192.168.48.100:/var/nfs_share_dir /mnt/nfs/var/nfs_share_dir nfs defaults 0 0
'


===============================================================




=============================================================================
### How to Upgrade Samba:
1- Stop Samba systemctl stop smb.service
2- kill command on smbd, nmbd, and winbindd
3- backup /etc/samba/
4- Find the location of the smbpasswd file and back it up to a safe location.
5- Find the location of the secrets.tdb file and back it up to a safe location
/var/lib/samba/private/secrets.tdb
6- Find the location of the lock directory:
/var/lib/samba directory. Copy all the tdb files to a safe location

7- It is now safe to upgrade the Samba installation. On Linux systems it is not necessary to remove the Samba RPMs because a simple upgrade installation will automatically remove the old files. 

8- Do not change the hostname.

9- Do not change the workgroup name.
10- Execute the testparm to validate the smb.conf file. This process will flag any parameters that are no longer supported. It will also flag configuration settings that may be in conflict. One solution that may be used to clean up and to update the smb.conf file involves renaming it to smb.conf.master and then executing the following:

root#  cd /etc/samba
root#  testparm -s smb.conf.master > smb.conf

======================================================
###  SMB Signing not required vunalabities
server signing = mandatory
OR
server signing = auto
client signing = auto

---------------------------------------------------
Raw
# firewall-cmd --permanent --new-service=samba-server
# firewall-cmd --permanent --service=samba-server --set-description="samba-server"
# firewall-cmd --permanent --service=samba-server --add-port=139-445/tcp
# firewall-cmd --permanent --add-service=samba-server
# firewall-cmd --reload

--------------------------------------
## share windows folder and mount into linux:
share on windows advantage-shared 
[root@ACHWorkstation ~]# yum install cifs-utils
[root@ACHWorkstation ~]# mkdir /EBC
[root@ACHWorkstation ~]# mount.cifs //172.17.77.182/ebc /EBC -o user=asadmin
Password for asadmin@//172.17.77.182/ebc:  ********


===================================================================================
#!/bin/sh

DATE=`date  '+%d%h%y.%H%M%S'`

ls /opt/shared/
if [ $? != 0 ]
then
mount -a
fi

rsync -avzhprEogt  --delete  172.17.84.84:/opt/shared/   /opt/shared/

if [ $? == 0 ]
then
echo $DATE >> /mnt/crontab-84/datesucc.txt
else
echo $DATE >> /mnt/crontab-84/dateserror.txt'

rsync -avz --remove-source-files -e ssh /this/dir remoteuser@remotehost:/remote/dir

=================================================================
#### Install TSM ba client 6.2  on Linux 6.0:
www.tsmtutorials.com 

$ tar -xvf 6.2.1.0-TIV-TSMBAC-LinuxX86.tar 
$ rpm -i gskcrypt32-8.2.13.3.linux.x86.rpm 
$ rpm -i gskssl32-8.2.13.3.linux.x86.rpm
$ rpm -i TIVSM-API.i386.rpm 
$ rpm -i TIVSM-BA.i386.rpm 
$ cd /opt/tivoli/tsm/client/ba/bin 

URL: https://T24BKP.hdbank.local:9081/bagui
admin/admin123
-----------------------------------
## tar:
tar -czvf name-of-archive.tar.gz /path/to/directory-or-file


----------------------------------------------------
[root@T24BKP 10. Oct 2019]# dsmc query backup PERF20191030_EndOfMonth
IBM Spectrum Protect
Command Line Backup-Archive Client Interface
  Client Version 8, Release 1, Level 10.0 
  Client date/time: 07/12/2020 13:37:33
(c) Copyright by IBM Corporation and other(s) 1990, 2020. All Rights Reserved. 

Node Name: T24-WAS-PROD
Session established with server TSM-HQ: Windows
  Server Version 8, Release 1, Level 5.000
  Server date/time: 07/12/2020 14:18:48  Last access: 07/12/2020 14:18:08

           Size        Backup Date                Mgmt Class           A/I File
           ----        -----------                ----------           --- ----
         4,096  B  07/12/2020 14:09:12             STANDARD             A  /backup/BackupPERF/PERF2019/10. Oct 2019/PERF20191030_EndO
fMonth
[root@T24BKP 10. Oct 2019]# 
'
------------------------------------------------------------------------------------
### NFS Error satus :
enum mountstat3 {
      MNT3_OK = 0,                 /* no error */
      MNT3ERR_PERM = 1,            /* Not owner */
      MNT3ERR_NOENT = 2,           /* No such file or directory */
      MNT3ERR_IO = 5,              /* I/O error */
      MNT3ERR_ACCES = 13,          /* Permission denied */
      MNT3ERR_NOTDIR = 20,         /* Not a directory */
      MNT3ERR_INVAL = 22,          /* Invalid argument */
      MNT3ERR_NAMETOOLONG = 63,    /* Filename too long */
      MNT3ERR_NOTSUPP = 10004,     /* Operation not supported */
      MNT3ERR_SERVERFAULT = 10006  /* A failure on the server */
   };

------------------------------------------------------------------
============================================================
####### Install Chrome browser: ##############
wget https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm
wget https://rpmfind.net/linux/centos/7.8.2003/os/x86_64/Packages/vulkan-1.1.97.0-1.el7.x86_64.rpm
wget https://rpmfind.net/linux/centos/7.8.2003/os/x86_64/Packages/vulkan-filesystem-1.1.97.0-1.el7.noarch.rpm
yum install vulkan-filesystem-1.1.97.0-1.el7.noarch.rpm 
yum install vulkan-1.1.97.0-1.el7.x86_64.rpm 
yum localinstall google-chrome-stable_current_x86_64.rpm

=======================================================================
### create large file:
[nathan@laobnas test]$ dd if=/dev/zero of=FROM_LA_TEST bs=1k count=4700000
4700000+0 records in
4700000+0 records out
4812800000 bytes (4.8 GB) copied, 29.412 seconds, 164 MB/s
[nathan@laobnas test]$ scp -C obnas:/obbkup/test/FROM_NY_TEST .
FROM_NY_TEST                                    3%  146MB   9.4MB/s   07:52 ETA

===============================================================
## Rsync 


## The best practical
rsync -avzhprEogt  /home/   172.17.7.183:/home/

-------------------------------------------------
#### rsync/   with (/) rsync content only 

[root@HDB00 rsync]# rsync -avzh /home/asadmin/rsync/ /tmp/ahmed/
sending incremental file list
./
test/
test/file1
test/file2
test/file3

[root@HDB00 rsync]# ls /tmp/ahmed/
     test/ 

   
### rsync directory with content them:

[root@HDB00 rsync]# rsync -avzh /home/asadmin/rsync /tmp/ahmed/
sending incremental file list
rsync/
rsync/test/
rsync/test/file1
rsync/test/file2
rsync/test/file3

sent 201 bytes  received 77 bytes  556.00 bytes/sec
total size is 0  speedup is 0.00
[root@HDB00 rsync]# ls /tmp/ahmed/
    rsync/            

------------------------------------------------------------------------
rsync -avz 172.17.7.17:/opt/disk2/amro-03-01-2018/backup84   shared/

## all content in backup84/ sync to shared/
a  archive
v  verpose
z  comprssion
r  recursive

====================================================
It efficiently copies and sync files to or from a remote system.
Supports copying links, devices, owners, groups and permissions.
It’s faster than scp (Secure Copy) because rsync uses remote-update protocol which allows to transfer just the differences between two sets of files. First time, it copies the whole content of a file or a directory from source to destination but from next time, it copies only the changed blocks and bytes to the destination.
Rsync consumes less bandwidth as it uses compression and decompression method while sending and receiving data both ends.

# rsync options source destination
-v : verbose
-r : copies data recursively (but don’t preserve timestamps and permission while transferring data
-a : archive mode, archive mode allows copying files recursively and it also preserves symbolic links, file permissions, user & group ownerships and timestamps
-z : compress file data
-h : human-readable, output numbers in a human-readable format


--------------------------
Copy/Sync a Directory on Local Computer
The following command will transfer or sync directory with all the files of in directory to a different directory in the same machine. Here in this example, /root/rpmpkgs contains some rpm package files and you want that directory to be copied inside /tmp/backups/ folder.

[root@tecmint]# rsync -avzh /root/rpmpkgs /tmp/backups/

sending incremental file list

rpmpkgs/

rpmpkgs/httpd-2.2.3-82.el5.centos.i386.rpm

rpmpkgs/mod_ssl-2.2.3-82.el5.centos.i386.rpm

rpmpkgs/nagios-3.5.0.tar.gz

rpmpkgs/nagios-plugins-1.4.16.tar.gz

sent 4.99M bytes  received 92 bytes  3.33M bytes/sec

total size is 4.99M  speedup is 1.00

------------------------------------------------------------
##Copy a File from a Remote Server to a Local Server with SSH
#To specify a protocol with rsync you need to give “-e” option with protocol name you want to use. Here in this example, We will be using “ssh” with “-e” option and perform data transfer.

[root@tecmint]# rsync -avzhe ssh root@192.168.0.100:/root/install.log /tmp/

root@192.168.0.100's password:

receiving incremental file list

install.log

sent 30 bytes  received 8.12K bytes  1.48K bytes/sec

total size is 30.74K  speedup is 3.77

------------------------------------------------------------------------
4. Show Progress While Transferring Data with rsync
To show the progress while transferring the data from one machine to a different machine, we can use ‘–progress’ option for it. It displays the files and the time remaining to complete the transfer.

[root@tecmint]# rsync -avzhe ssh --progress /home/rpmpkgs root@192.168.0.100:/root/rpmpkgs

root@192.168.0.100's password:

sending incremental file list

created directory /root/rpmpkgs

rpmpkgs/

rpmpkgs/httpd-2.2.3-82.el5.centos.i386.rpm

           1.02M 100%        2.72MB/s        0:00:00 (xfer#1, to-check=3/5)

rpmpkgs/mod_ssl-2.2.3-82.el5.centos.i386.rpm

          99.04K 100%  241.19kB/s        0:00:00 (xfer#2, to-check=2/5)

rpmpkgs/nagios-3.5.0.tar.gz

           1.79M 100%        1.56MB/s        0:00:01 (xfer#3, to-check=1/5)

rpmpkgs/nagios-plugins-1.4.16.tar.gz

           2.09M 100%        1.47MB/s        0:00:01 (xfer#4, to-check=0/5)

sent 4.99M bytes  received 92 bytes  475.56K bytes/sec

total size is 4.99M  speedup is 1.00

------------------------------------------------------------------------
5. Use of –include and –exclude Options
These two options allows us to include and exclude files by specifying parameters with these option helps us to specify those files or directories which you want to include in your sync and exclude files and folders with you don’t want to be transferred.

Here in this example, rsync command will include those files and directory only which starts with ‘R’ and exclude all other files and directory.

[root@tecmint]# rsync -avze ssh --include 'R*' --exclude '*' root@192.168.0.101:/var/lib/rpm/ /root/rpm

root@192.168.0.101's password:

receiving incremental file list

created directory /root/rpm

./'

Requirename

Requireversion

sent 67 bytes  received 167289 bytes  7438.04 bytes/sec

total size is 434176  speedup is 2.59

-------------------------------------------------------------------------
6. Use of –delete Option
If a file or directory not exist at the source, but already exists at the destination, you might want to delete that existing file/directory at the target while syncing .

We can use ‘–delete‘ option to delete files that are not there in source directory.

Source and target are in sync. Now creating new file test.txt at the target.

[root@tecmint]# touch test.txt
[root@tecmint]# rsync -avz --delete root@192.168.0.100:/var/lib/rpm/ .
Password:
receiving file list ... done
deleting test.txt
./
sent 26 bytes  received 390 bytes  48.94 bytes/sec
total size is 45305958  speedup is 108908.55
Target has the new file called test.txt, when synchronize with the source with ‘–delete‘ option, it removed the file test.txt.

------------------------------------------------------------------------------------------
7. Set the Max Size of Files to be Transferred
You can specify the Max file size to be transferred or sync. You can do it with “–max-size” option. Here in this example, Max file size is 200k, so this command will transfer only those files which are equal or smaller than 200k.

[root@tecmint]# rsync -avzhe ssh --max-size='200k' /var/lib/rpm/ root@192.168.0.100:/root/tmprpm

root@192.168.0.100's password:

sending incremental file list

created directory /root/tmprpm

./'

Conflictname

Group

Installtid

Name

Provideversion

Pubkeys

Requireversion

Sha1header

Sigmd5

Triggername

__db.001

sent 189.79K bytes  received 224 bytes  13.10K bytes/sec

total size is 38.08M  speedup is 200.43

---------------------------------------------------------------------------------
8. Automatically Delete source Files after successful Transfer
Now, suppose you have a main web server and a data backup server, you created a daily backup and synced it with your backup server, now you don’t want to keep that local copy of backup in your web server.

So, will you wait for transfer to complete and then delete those local backup file manually? Of Course NO. This automatic deletion can be done using ‘–remove-source-files‘ option.

[root@tecmint]# rsync --remove-source-files -zvh backup.tar /tmp/backups/

backup.tar

sent 14.71M bytes  received 31 bytes  4.20M bytes/sec

total size is 16.18M  speedup is 1.10

[root@tecmint]# ll backup.tar

ls: backup.tar: No such file or directory

-----------------------------------------------------------------------------------------
10. Set Bandwidth Limit and Transfer File
You can set the bandwidth limit while transferring data from one machine to another machine with the the help of ‘–bwlimit‘ option. This options helps us to limit I/O bandwidth.

[root@tecmint]# rsync --bwlimit=100 -avzhe ssh  /var/lib/rpm/  root@192.168.0.100:/root/tmprpm/
root@192.168.0.100's password:
sending incremental file list
sent 324 bytes  received 12 bytes  61.09 bytes/sec
total size is 38.08M  speedup is 113347.05
'
---------------------------------------------------------------------------------------------------
1) Rsync daemon server:
The Rsync server is often referred to as rsyncd or the rsync daemon. This is in fact the same rsync executable run with the command line argument "--daemon". This can be run stand-alone or using xinetd as is typically configured on most Linux distributions.

Configure xinetd to manage rsync:
File: /etc/xinetd.d/rsync

Default: "disable = yes". Change to "disable = no"

view sourceprint?
01
$ vim  /etc/xinetd.d/rsync
service rsync
{
        disable = no
        flags           = IPv6
        socket_type     = stream
        wait            = no
        user            = root
        server          = /usr/bin/rsync
        server_args     = --daemon
        log_on_failure  += USERID
}

$ /etc/rc.d/init.d/xinetd restart


 $ vim /etc/rsyncd.conf
'
log file = /var/log/rsyncd.log
hosts allow = 192.17.39.244, 192.17.39.60
hosts deny = *
list = true
uid = root
gid = root
read only = false
[Proj1]
path = /tmp/Proj1
comment = Project 1 rsync directory
[ProjX]
path = /var/ProjX
comment = Project X rsync directory
'

----------------------------------------------
## The best practical
rsync -avzhprEogt  /home/   172.17.7.183:/home/

=====================================================
### Error with rsync

$ rsync -avz /images/* cdn.example.com:/images/

-bash: /usr/bin/rsync: Argument list too long
The solution is to either remove the “*” from the source as in the following example:


$ rsync -avz /images/ cdn.example.com:/images/

Or do things a little smarter. Here’s the two step process. Here’s how to do it.

Create a list of the files (in this case we want pictures) you want to copy:

find /images/ -name *.png > /tmp/my_image_list.txt

And now we feed that into rsync:

$ rsync -avz --files-from=/tmp/my_image_list.txt / cdn.example.com:/images/


============================================================================
==================================================================================================
## Add virtual IP on the same interface
For Linux:
ifconfig <secondary_interface_name> <virtual_ip_address> netmask <netmask>
For example:
ifconfig eth0:0 10.10.20.218 netmask 255.255.255.0

For Linux:
ifconfig <secondary_interface_name> del <virtual_ip_address>
For example:
ifconfig eth0:0 del 10.10.20.218

====================================================================
## network on Ubuntu 20
vim /etc/netplan/00-installer-config.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses:
        - 192.168.100.10/24
      routes:
        - to: default
          via: 192.168.100.1
      nameservers:
          search: [linkdev.local]
          addresses: [192.168.100.1, 1.1.1.1, 8.8.8.8]

-------------------------
# This is the network config written by 'subiquity'
network:
  ethernets:
    ens33:
       addresses: [172.17.90.55/24]
       gateway4: 172.17.90.90
       nameservers:
         addresses: [172.17.15.35,172.30.15.35]
       routes:
       - to: 172.250.1.0/24
         via: 172.17.90.90
  version: 2
  
---------------
netplan apply

ysadm@linuxtechi:~$ ip add show
sysadm@linuxtechi:~$ ip route show

==========================================
### check softlink
ls -la /var/www/ | grep "\->
"
======================================================
### du 
du -hsx /opt/shared/hdbatm/* | sort -rh | head -10
'
==========================================================
### uppack iso or extract :
mount -o loop ubuntu-16.10-server-amd64.iso /mnt/iso

==========================================================
createrepo -v /var/www/html/opt/repo/

============================================
cat << EOF > /tmp/yourfilehere
These contents will be written to the file.
        This line is indented.
EOF

=========================================
### Swapon 
swapon /dev/mapper/rootvg-swap 

swapoff -v /dev/mapper/rootvg-swap

-----------------------------------------------------------
## How to extend SWAP, swap is part of rootvg
[root@T24-Access ~]# swapoff -v /dev/mapper/rootvg-swap

[root@T24-Access ~]# pvcreate /dev/sdb1
[root@T24-Access ~]# vgextend rootvg /dev/rootvg/
'root  swap'

[root@T24-Access ~]# vgextend rootvg /dev/sdb1

[root@T24-Access ~]# lvresize /dev/mapper/rootvg-swap -L +4.5G
'
  Size of logical volume rootvg/swap changed from 4.00 GiB (1024 extents) to 8.50 GiB (2176 extents).
  Logical volume rootvg/swap successfully resized.
'

[root@T24-Access ~]# mkswap /dev/rootvg/swap 
'
mkswap: /dev/rootvg/swap: warning: wiping old swap signature.
Setting up swapspace version 1, size = 8912892 KiB
no label, UUID=029ad523-b3b8-4717-8696-5aa4c400b0cf
''
swapon /dev/mapper/rootvg-swap 


[root@T24-Access ~]# cat /proc/swaps
Filename                                Type            Size    Used    Priority
/dev/dm-1                               partition       8912892 0       -2
[root@T24-Access ~]# free
              total        used        free      shared  buff/cache   available
Mem:        8009056      224768     7287632       25476      496656     7513252
Swap:       8912892           0     8912892

================================================================================='
####### Extend rootvg 

fdisk /dev/sdc 
[root@sas-share ~]# pvcreate /dev/sdc1

[root@sas-share ~]# vgextend rootvg /dev/sdc1 
  Volume group "rootvg" successfully extended

[root@sas-share ~]# lvresize /dev/mapper/rootvg-root -l +100%FREE
  Size of logical volume rootvg/root changed from 109.99 GiB (28158 extents) to 209.99 GiB (53758 extents).
  Logical volume rootvg/root successfully resized.


[root@sas-share ~]# xfs_growfs /dev/mapper/rootvg-root 
meta-data=/dev/mapper/rootvg-root isize=512    agcount=4, agsize=7208448 blks
         =                       sectsz=512   attr=2, projid32bit=1
         =                       crc=1        finobt=0 spinodes=0
data     =                       bsize=4096   blocks=28833792, imaxpct=25
         =                       sunit=0      swidth=0 blks
naming   =version 2              bsize=4096   ascii-ci=0 ftype=1
log      =internal               bsize=4096   blocks=14079, version=2
         =                       sectsz=512   sunit=0 blks, lazy-count=1
realtime =none                   extsz=4096   blocks=0, rtextents=0
data blocks changed from 28833792 to 55048192

in case ext4 
$ resize2fs /dev/nfsvg/nfslv

--------------------------------------------------------------------------------
wget http://public-yum.oracle.com/public-yum-ol6.repo
yum update

'

##  Script for parted and vgm
'
#!/bin/sh
echo -n "Please enter a disk (ex sdb): "
read disk
parted -s /dev/$disk  mklabel  gpt
parted -s /dev/$disk unit mib mkpart primary 1 100%
parted -s /dev/$disk  set  1 lvm on
parted /dev/$disk print

echo "##########  Create FS ###############"
echo -n "Please enter a disk (ex sdb1): "
read disk
pvcreate /dev/$disk

echo -n "Please enter an name of VG (ex datavg): "
read vgname
vgcreate $vgname /dev/$disk

echo -n "Please enter an name of LV (ex datalv): "
read lvname
lvcreate -n $lvname -l 100%FREE $vgname

echo -n "Please enter an type of fs (ex xfs): "
read fs
mkfs.$fs  /dev/mapper/$vgname-$lvname

echo "######   Mount FS ###############"
echo -n "Please enter an path of mount (ex /u01): "
read mfs
mkdir -p $mfs 
echo "/dev/mapper/$vgname-$lvname   $mfs   $fs  defaults 0 0" >> /etc/fstab 
systemctl daemon-reload

mount $mfs 
df -h 
'

$ fdisk -l

$ fdisk /dev/sdb
m n 1 default default  w

$ pvcreate /dev/sdb1 /dev/sdc1

$ vgcreate VG_NAME /dev/sdb1 /dev/sdc1

$lvcreate -L 2G VG_NAME -n LV0
$lvcreate -L 100M VG_NAME -n LV1

$ lvcreate -n LV_NAME -l 100%FREE VG_NAME

$ mkfs.xfs /dev/mapper/LV_NAME

$ mount /dev/mapper/LV_NAME  /mnt 

$ edit fstab

$ pvdisplay
$ vgdisplay 
$ lvdisplay

-----------------------------
#creates a logical volume called mylv that uses 60% of the total space in volume group testvol.

lvcreate -l 60%VG -n mylv testvg

#creates a logical volume called yourlv that uses all of the unallocated space in the volume group testvol.

lvcreate -l 100%FREE -n yourlv testvg

-------------------------------------------
### Delete
 $ pvdisplay
 $ vgdisplay 
 $lvdisplay

 
[root@T24BKP ~]# umount  /backup

[root@T24BKP ~]#  lvchange -an /dev/t24vg/t24lv 

[root@T24BKP ~]# lvremove /dev/t24vg/t24lv
  Logical volume "t24lv" successfully removed

[root@T24BKP ~]# vgchange -an t24vg
  0 logical volume(s) in volume group "t24vg" now active

[root@T24BKP ~]# vgremove t24vg
  Volume group "t24vg" successfully removed

[root@T24BKP ~]# pvremove /dev/sdb
sdb   sdb1  

[root@T24BKP ~]# pvremove /dev/sdb1
  Labels on physical volume "/dev/sdb1" successfully wiped
[root@T24BKP ~]# fdisk /dev/sdb1 # delete

================================================


'===========================================================================================
### extend the same harddisk on VMWare 
$ ls /sys/class/scsi_device/

##Then rescan the scsi bus. Below you can replace the '0\:0\:0\:0′ with the actual scsi bus name found with the previous command. Each colon is prefixed with a slash, which is what makes it look weird.

~$ echo 1 > /sys/class/scsi_device/0\:0\:0\:0/device/rescan

=================================================================================
### Backup filesystem:
----
Step 0. Lab Preparation:
– Create a primary lvm partition using fdisk with 2 Gib size:

# fdisk /dev/sdb
# partprobe

– Create a physical volume:
# pvcreate /dev/sdb1 # create a physical volume

– Create a volume group with an extent size of 16M:
# vgcreate -s 16M vg00 /dev/sdb1 
# vgcreate vg00 /dev/sdb1 

– Create logical volume with size of 800M (50 extents)
# lvcreate -L 800M -n lv00 vg00 
OR
# lvcreate -n vol_projects -L 10G vg00
# lvcreate -n vol_backups -l 100%FREE vg00

– Convert the logical volume to xfs file system
# mkfs.xfs /dev/vg00/lv00

– Mount the partition to a directory
# mkdir /test 
# mount /dev/vg00/pv00 /test

– Create some file in the directory
# dd if=/dev/zero of=/test/file01 bs=1024k count=10
# dd if=/dev/zero of=/test/file02 bs=1024k count=10
# dd if=/dev/zero of=/test/file03 bs=1024k count=10

– Install the xfsdump package
# yum install xfsdump -y


Step 1. Backup The Data
# xfsdump -f /tmp/test.dump /test

Step 2. Unmount The Partition
# umount /test

Step 3. Reduce The Partition Size
# lvreduce -L 400M /dev/vg00/lv00

Step 4. Format The Partition With XFS Filesystem
# mkfs.xfs -f /dev/vg00/lv00

Step 5. Remount the Parition
# mount /dev/vg00/lv00 /test

-------------------------------
## Usig UUID in fstab
$ uuidgen
39ea80c4-e748-47eb-835c-64025de53e26

 sudo umount /dev/sdb1

 #Use the tune2fs command to assign the new UUID to the partition.
sudo tune2fs /dev/sdb1 -U 39ea80c4-e748-47eb-835c-64025de53e26
OR 
sudo tune2fs /dev/mapper/kvmvg-kvmlv -U 39ea80c4-e748-47eb-835c-64025de53e26
# IF disk xfs 
 xfs_admin  -U 287d622b-f7d2-4ef8-a266-25522426ca84 /dev/mapper/kvmvg-kvmlv

#Verify that the UUID has been successfully assigned to the partition.
sudo blkid /dev/sdb1
#/dev/sdb1: UUID="39ea80c4-e748-47eb-835c-64025de53e26" TYPE="ext4" PARTUUI

===============================================================================================
### How to move vg from VM to VM: 
# Moving a VG to another server

[root@T24-Access ~]# umount /app
[root@T24-Access ~]# vgchange -an vg00

[root@T24-Access ~]# vgexport vg00
 vgexport -- volume group "vg00" successfully exported


enter in datastore and click on [move to] disk to other VM   

 ### Other VM 
[root@T24-Access ~]# pvscan
'
pvscan -- reading all physical volumes (this may take a while...)
pvscan -- inactive PV "/dev/sdc1" is in EXPORTED VG "appvg" [996 MB / 996 MB free]
pvscan -- inactive PV "/dev/sdc2" is in EXPORTED VG "appvg" [996 MB / 244 MB free]
pvscan -- total: 2 [1.95 GB] / in use: 2 [1.95 GB] / in no VG: 0 [0] 
'

[root@T24-Access ~]# vgimport appvg
Volume group "vg" successfully imported

[root@T24-Access ~] vgchange -ay appvg
[root@T24-Access ~]# mkdir -p /appdata
[root@T24-Access ~]# mount /dev/appvg/appdata /appdata

--------------------------------------------------------
#Linux: How to delete a disk or LUN reference from /dev


#  Make sure that the disk is not being used by the application, does not contain a mounted file system or an active volume group.
1. Take the disk offline:
cd /sys/block/sdb/device
 echo “offline” > state

2. Delete from /dev
echo 1 >delete

#You can make your own script with the name rmdev 😉
---
#!/bin/ksh
dev=$1
[[ ! -d "$dev" ]] && echo "$dev does not exist" && exit 1
echo "offline" >/sys/block/"$dev"/device/state
echo 1 >/sys/block/"$dev"/device/delete
----
$ rmdev sdc 
==============================================
### MySQL:

[root@host]# mysqladmin --version

[root@host]# rpm -i MySQL-client-5.0.9-0.i386.rpm
[root@host]# rpm -i MySQL-devel-5.0.9-0.i386.rpm
[root@host]# rpm -i MySQL-shared-5.0.9-0.i386.rpm
[root@host]# rpm -i MySQL-bench-5.0.9-0.i386.rpm

'#### Install on Rdhat 8
[root@hdb00 ~]# yum install mysql-server

[root@hdb00 ~]# systemctl start mysqld
[root@hdb00 ~]# systemctl enable  mysqld

sudo firewall-cmd --add-service=mysql --permanent
sudo firewall-cmd --reload

You can also limit access from trusted networks:

sudo firewall-cmd --permanent --add-rich-rule 'rule family="ipv4" \
service name="mysql" source address="10.10.10.0/24" accept'

'

firewall-cmd --permanent --add-port=139/tcp
firewall-cmd --permanent --add-port=445/tcp
firewall-cmd --permanent --add-port=137/udp
firewall-cmd --permanent --add-port=138/udp
firewall-cmd --reload

======================================================================
=====================================================================
### Install VMware Tool
[root@virtualmachine]$  mkdir /mnt/cdrom
[root@virtualmachine]$  mount /dev/cdrom /mnt/cdrom

[root@virtualmachine]$  cp /mnt/cdrom/VMwareTools*.tar.gz /tmp/
[root@virtualmachine]$  cd /tmp/
[root@virtualmachine]$  tar xvfz VMwareTools*.tar.gz

=========================================================================
========================================================================
###################  Reinstalling the Boot Loader
In many cases, the GRUB boot loader can mistakenly be deleted, corrupted, or replaced by other operating systems.
The following steps detail the process on how GRUB is reinstalled on the master boot record:

1- Boot the system from an installation boot medium.
2-  linux rescue at the installation boot prompt to enter the rescue environment.
3-  chroot /mnt/sysimage to mount the root partition.
4-  /sbin/grub-install /dev/hda to reinstall the GRUB boot loader, where /dev/hda is the boot partition.
5- Review the /boot/grub/grub.conf file, as additional entries may be needed for GRUB to control additional operating systems.
6- Reboot the system.
'
============================= Boom Boot Manager ================================================================
{https://www.redhat.com/en/blog/boom-booting-rhel-lvm-snapshots}

#### Boom! Booting RHEL from LVM snapshots
yum install lvm2-python-boom

# vgs
 VG      #PV #LV #SN Attr   VSize VFree
 rhel_rhel7   2 2 0 wz--n- 48.99g <30.00g
#
# lvs
 LV   VG   Attr    LSize   Pool Origin Data%  Meta% Move Log Cpy%Sync Convert
 root rhel_rhel7 -wi-ao---- <17.00g                                               
 swap rhel_rhel7 -wi-ao----   2.00g

 '
The rhel_rhel7 volume group has enough available free space to create a snapshot logical volume for the root logical volume. Remember to properly size your snapshots because if the snapshot fills up, it becomes invalid.
 '

#Getting Started with Boom

# lvcreate -s rhel_rhel7/root -n root_snapshot_071018 -L 17G
 Logical volume "root_snapshot_071018" created.


'
The “-s” specifies the volume group/logical volume name of the logical volume we want to create a snapshot of. The “-n” specifies a name for the snapshot logical volume (in our case the name will be “root_snapshot_071018”), and the “-L” specifies the size of the snapshot logical volume, which in our example is 17 GB. 
'
#Then, we will use boom to create a boot entry for this snapshot by running

$ boom create --title "Root Snapshot - 07/10/18" --rootlv rhel_rhel7/root_snapshot_071018
'
WARNING - Boom configuration not found in grub.cfg
WARNING - Run 'grub2-mkconfig > /boot/grub2/grub.cfg' to enable
Created entry with boot_id d2c8369:
 title Root Snapshot - 07/10/18
 machine-id 1181b7e44d6845e38a9dc3257af5d56b
 version 3.10.0-862.6.3.el7.x86_64
 linux /vmlinuz-3.10.0-862.6.3.el7.x86_64
 initrd /initramfs-3.10.0-862.6.3.el7.x86_64.img
 options root=/dev/rhel_rhel7/root_snapshot_071018 ro rd.lvm.lv=rhel_rhel7/root_snapshot_071018 rhgb quiet
'
'
The “--title” option on the boom command specifies what title should be shown from the grub2 menu, and the “--rootlv” specifies the volume group/snapshot logical volume name, which in our example is rhel_rhel7/root_snapshot_071018.

Notice that when we ran the boom create command, it came back with a warning that the boom configuration was not found in grub.cfg, and recommended the solution to this.   We will go ahead and run the command it specified in the warning:
'

$grub2-mkconfig > /boot/grub2/grub.cfg
 
'
Generating grub configuration file ...
Found linux image: /boot/vmlinuz-3.10.0-862.6.3.el7.x86_64
Found initrd image: /boot/initramfs-3.10.0-862.6.3.el7.x86_64.img
Found linux image: /boot/vmlinuz-3.10.0-862.el7.x86_64
Found initrd image: /boot/initramfs-3.10.0-862.el7.x86_64.img
Found linux image: /boot/vmlinuz-0-rescue-1181b7e44d6845e38a9dc3257af5d56b
Found initrd image: /boot/initramfs-0-rescue-1181b7e44d6845e38a9dc3257af5d56b.img
done
'
'At this point, we have created a snapshot of the root logical volume, and configured boom to make the snapshot bootable via the grub2 menu.'

#We can see what snapshots boom is configured to use by running boom list:

$ boom list
BootID  Version               Name                         RootDevice                     
d2c8369 3.10.0-862.6.3.el7.x86_64 Red Hat Enterprise Linux Server /dev/rhel_rhel7/root_snapshot_071018

### Test snapshot:
Next, we will make some changes to the system

# yum install tmux screen
# useradd newuser
# echo password | passwd newuser --stdin

vim /etc/sudoers.d/newuser 
'
newuser ALL=(root) NOPASSWD:ALL 
'
chmod 0400 /etc/sudoers.d/newuser

# echo “Updated motd file, after snapshot was taken” > /etc/motd

#At this point, we will reboot the server and see what it looks like from the grub2 menu:
'
Red Hat Enterprise ......
..
..
Snapshts 
'
The tmux and screen packages are not installed:

# yum list installed | egrep "screen|tmux"

The “newuser” account doesn’t exist:

# id newuser
id: newuser: no such user

# cat /proc/cmdline

BOOT_IMAGE=(hd0,msdos1)/vmlinuz-3.10.0-862.6.3.el7.x86_64 root=/dev/rhel_rhel7/root_snapshot_071018 ro rd.lvm.lv=rhel_rhel7/root_snapshot_071018 rhgb quiet

'Next, we will reboot, and let the system boot normally (not from the snapshot) and clean up the snapshot.'

'# yum list installed | egrep "screen|tmux"
screen.x86_64                     4.1.0-0.25.20120314git3c2946.el7
tmux.x86_64                       1.8-4.el7            @rhel-7-server-rpms
# id newuser
uid=1000(newuser) gid=1000(newuser) groups=1000(newuser)
# cat /etc/motd
Updated motd file, after snapshot was taken'

####To remove the snapshot from boom, first run boom list to get the BootID for the snapshot:

# boom list
BootID  Version               Name                         RootDevice                     
d2c8369 3.10.0-862.6.3.el7.x86_64 Red Hat Enterprise Linux Server /dev/rhel_rhel7/root_snapshot_07

$ boom entry delete d2c8369
Deleted 1 entry

$ boom list
BootID  Version              Name                  RootDevice


Next, delete the snapshot logical volume with the lvremove command:

# lvremove rhel_rhel7/root_snapshot_071018
Do you really want to remove active logical volume rhel_rhel7/root_snapshot_071018? [y/n]: y
 Logical volume "root_snapshot_071018" successfully removed

##### Merging the snapshot back into the Original Logical Volume

$lvconvert --merge /dev/rhel_rhel7/root_snapshot_071018 
 Delaying merge since snapshot is open.
 Merging of snapshot rhel_rhel7/root_snapshot_071018 will occur on next activation of rhel_rhel7/root.

-------------------------------------------------------------------------


lsinitrd

# list of initrdfs
==================================================================================================
==================================================================================================
### How to create the chroot from Rescue Mode?
$ mkdir -p /mnt/sysimage/

# Find the /boot/ partition:
$ fdisk -l
# lvm pvscan
# lvm vgscan
# lvm lvscan
# lvs 

#We will use the example: /dev/mapper/vg-lv

Make sure the volume group containing the root filesystem has been activated:

$ vgchange -ay "vg"

Mount the root storage, then mount the /boot filesystem inside the root filesystem:

# mount /dev/mapper/vg-lv /mnt/sysimage/
# mount /dev/sda1 /mnt/sysimage/boot/

Bind-mount the virtual filesystems required for chroot:

# mount /proc /mnt/sysimage/proc/ -o bind
# mount /dev /mnt/sysimage/dev/ -o bind
# mount /sys /mnt/sysimage/sys/ -o bind

Bind-mount additional virtual filesystems (optional):

# mount /dev/pts /mnt/sysimage/dev/pts -o bind

Enter the chroot:

# chroot /mnt/sysimage/

============================================================
###change  uname 
$ mv /bin/uname  /bin/uname.old

root@HDB84N1# vim /bin/uname
#!/bin/bash
/bin/uname.old -n $*

chmod 755 /bin/uname 


---------------------------------------------------------
=================================================
### Setting date
root@HDB84# unlink /etc/localtime                              
root@HDB84# ln -s /usr/share/zoneinfo/Etc/GMT+1  /etc/localtime 
root@HDB84# date
Fri Dec 11 16:58:32 GMT+1 2020
root@HDB84# timedatectl set-time 19:15:00

OR
timedatectl set-time "2019-10-13 20:36:00"
'
---------------------------------------------------------------
timedatectl status
timedatectl list-timezones | grep "America/" | less
timedatectl set-timezone "America/Edmonton"
timedatectl set-time 10:30:00
sudo systemctl stop systemd-timesyncd.service

sudo systemctl start systemd-timesyncd.service



==================================================================
### Kill users by kill you jobs
root@HDB84# users
operator operator operator operator root root root
root@HDB84# ps -u
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root       410  0.3  0.0   1120   592 pts/6    S+   18:47   0:07 runcobol /home/operator/rcvdfils -k -c /home/operator/config.f
root       959  0.0  0.0 110028   848 tty1     Ss+  15:22   0:00 /sbin/agetty --noclear tty1 linux
root      2074  0.0  0.0   9508  1296 pts/0    Ss+  15:23   0:00 /bin/sh /home/operator/oper.sh
root      2077  0.0  0.0   1144   644 pts/0    S+   15:23   0:00 runcobol fkryopr -c /usr/bin/config.f -k
root      2610  0.0  0.0 117416  1932 pts/3    Ss   19:11   0:00 -bash

root@HDB84# ps -ef | grep operator
root       410 31338  0 18:47 pts/6    00:00:08 runcobol /home/operator/rcvdfils -k -c /home/operator/config.f
root      1877  1865  0 15:22 ?        00:00:00 login -- operator
root      2074  1877  0 15:23 pts/0    00:00:00 /bin/sh /home/operator/oper.sh
root     13765 13615  0 18:47 ?        00:00:00 login -- operator
root     15413 13765  0 18:47 pts/4    00:00:00 /bin/sh /home/operator/oper.sh
root@HDB84# kill 2074

======================================================================================
===================================
## Register RHEL
'
export http_proxy="http://sas.watchlist:asd1010%40@172.17.0.25:8080/"
export https_proxy="https://sas.watchlist:asd1010%40@172.17.0.25:8080/"
'
subscription-manager register  --proxy=http://172.17.0.25:8080/ --username=sas.watchlist --password=asd1010@
'
========================================================================================
### Create local repo on RHEL 8.3
### RHEL 8 Repo
# Create repository directory
sudo mkdir -p /var/repo/rhel9

# Copy contents (preserving permissions)
sudo cp -r /mnt/rhel-iso/* /var/repo/rhel9/


# Install createrepo if needed
sudo dnf install -y createrepo_c

# Create repository metadata
sudo createrepo_c /var/repo/rhel9/AppStream
sudo createrepo_c /var/repo/rhel9/BaseOS

sudo tee /etc/yum.repos.d/local-rhel9.repo << 'EOF'
[local-rhel9-BaseOS]
name=Local RHEL 9 - BaseOS
baseurl=file:///var/repo/rhel9/BaseOS
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

[local-rhel9-AppStream]
name=Local RHEL 9 - AppStream
baseurl=file:///var/repo/rhel9/AppStream
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
EOF

sudo rpm --import /var/repo/rhel9/RPM-GPG-KEY-redhat-release

# Clean DNF cache
sudo dnf clean all

# List enabled repositories
sudo dnf repolist

# Test the repository
sudo dnf --disablerepo="*" --enablerepo="local-rhel9*" list available


=======================================================================================
### Redhat 8 repo: ##########
  [ol8_baseos_latest]
  name=Oracle Linux 8 BaseOS Latest ($basearch)
  baseurl=https://yum$ociregion.oracle.com/repo/OracleLinux/OL8/baseos/latest/$basearch/
  gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
  gpgcheck=1
  enabled=1

  [ol8_appstream]
  name=Oracle Linux 8 Application Stream ($basearch)
  baseurl=https://yum$ociregion.oracle.com/repo/OracleLinux/OL8/appstream/$basearch/
  gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
  gpgcheck=1
  enabled=1

=================================================================
### Repol bu file
[rhel8_appstream]
name=file repository
baseurl=file:///rhel8.3/AppStream/Packages/
enable=1
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

[rhel8_baseos_latest]
name=file repository
baseurl=file:///rhel8.3/BaseOS/Packages/
enable=1
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

===================================================
## Final Repo on RHEL 8.3
[httpAppStream]
name=http repository
baseurl=http://172.250.1.119/rhel/8.4/AppStream/
enable=1
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release


[httpBaseOS]
name=http repository
baseurl=http://172.250.1.119/rhel/8.4/BaseOS/
enable=1
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

===================================
## local 
[local.repo]
name=local.repo
baseurl=file:///data/rhel/8.3/BaseOS/
enabled=0
gpgcheck=0


[local1.repo]
name=local.repo
baseurl=file:///data/rhel/8.3/AppStream/
enabled=0
gpgcheck=0
'
=============================================================
### creat repo by FTP  from ISO 
mount ISO on /mnt 
mount -o loop rhel-server-7.3-x86_64-dvd.iso /mnt/

cp -rf /mnt/*  /var/ftp/pub/dvd/ 

mkdir -p /var/ftp/pub/dvd 
 
cd /var/ftp/pub/dvd/repodata  

cp 833h44hfef0sdia0d0d0d0fdd-comps-server.x86_64.xml /var/ftp/pub/groups.xml 

createrepo -vg /var/ftp/pub/dvd/groups.xml /var/ftp/pub/dvd/ 

cd /etc/yum.repos.d/
vi yum-server.repo 
'
prhel_7.2_dvd]
name=RHEL7.2 
baseurl=file:///var/ftp/pub/dvd 
enabled=1
gpgcheck=0
'

####################################################
##

========================================================
repo 'appstream': Cannot prepare internal mirrorlist
Curl error (6): Couldn't resolve host name for http://mirrorlist.centos.org/?release=8&arch=x86_64&repo=AppStream&infra=vag [Could not resolve host: mirrorlist.centos.org]


RUN cd /etc/yum.repos.d/
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
RUN sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
dnf update -y

=====================================================
## Comment all lines in file 
sed -i 's/^/#/' /etc/elasticsearch/elasticsearch.yml
# Commenting All Lines in a File Using `sed` in Linux

Here are several methods to comment out all lines in a file using `sed`:

## Method 1: Basic Commenting (Prepend # to all lines)
```bash
sed -i 's/^/#/' filename
```

## Method 2: Preserve Whitespace (Only comment non-empty lines)
```bash
sed -i '/^$/! s/^/#/' filename
```

## Method 3: In-Place Editing with Backup
```bash
sed -i.bak 's/^/#/' filename  # Creates filename.bak backup
```

## Method 4: Using Different Comment Characters
For different file types:
- Shell/Config files (use `#`):
  ```bash
  sed -i 's/^/#/' filename.conf
  ```
- SQL (use `--`):
  ```bash
  sed -i 's/^/-- /' filename.sql
  ```
- C/C++ (use `//`):
  ```bash
  sed -i 's/^/\/\//' filename.c
  ```

## Method 5: Commenting with Line Numbers
```bash
sed -i '1,$ s/^/#/' filename  # Explicitly specify line range
```

## Method 6: Using Address Ranges
```bash
sed -i '1,$ {s/^/#/}' filename
```

## To Undo/Comments (Uncomment all lines):
```bash
sed -i 's/^#//' filename
```

## Important Notes:
1. The `-i` flag does in-place editing (use `-i.bak` to create backup)
2. For special characters in filenames, use:
   ```bash
   sed -i 's/^/#/' "file name with spaces"
   ```
3. To preview changes before modifying:
   ```bash
   sed 's/^/#/' filename | less
   ```
##############################
Here's how to comment out all lines in a file using the **Vi/Vim** editor:

### **Method 1: Block Comment (Visual Mode)**
1. Open the file in Vi:
   ```bash
   vi filename
   ```
2. Enter **visual block mode**:
   ```
   Ctrl + V
   ```
3. Select all lines:
   - Press `G` to go to the end of the file (or use `j`/`k` to select manually).
4. Insert comment character (e.g., `#` for shell/configs):
   ```
   Shift + I
   #
   Esc
   ```
   - After pressing `Esc`, the comment character will be added to all selected lines.

---

### **Method 2: Substitute Command (For Any Language)**
1. In Vi, run this command to prepend `# ` to all lines:
   ```
   :%s/^/# /
   ```
   - Replace `#` with:
     - `//` for C/Java/JavaScript
     - `--` for SQL
     - `"` for Vimscript
     - `%` for LaTeX

2. For **removing comments** later:
   ```
   :%s/^# //
   ```

---

### **Method 3: Line-Range Comment**
To comment lines 5–20:
```
:5,20s/^/# /
```

---

### **Method 4: External Filter (For Large Files)**
1. Use `sed` from within Vi:
   ```
   :%!sed 's/^/# /'
   ```

---

### **Examples for Different File Types**
| **File Type** | **Command**              | **Uncomment Command**     |
|---------------|--------------------------|---------------------------|
| Shell/Python  | `:%s/^/# /`             | `:%s/^# //`              |
| C/C++/Java    | `:%s/^/\/\//`           | `:%s/^\/\///`            |
| SQL           | `:%s/^/-- /`            | `:%s/^-- //`             |
| XML/HTML      | `:%s/^/<!-- /` + `:%s/$/ -->/` | `:%s/<!-- //g` + `:%s/ -->//g` |

---

### **Bonus: Toggle Comments with a Macro**
1. Record a macro (e.g., `q`):
   ```
   qq0i# <Esc>jq
   ```
2. Execute it on all lines:
   ```
   :%norm @q
   ```

---

### **Notes:**
- For **YAML**, ensure comments start with `#` at column 0.
- For **JSON** (which doesn’t natively support comments), use `//` if your parser allows it.
- Use `:set nu` to show line numbers for precision.

Need this for a specific file type? Let me know!

###################################################################
# uncomment all lines in vi editor

:%s/^# //
======================================================
## HighAvailability

[localrhel7]
name=RHEL7_Base
baseurl=file:///data/rhel7_repo
enabled=1
gpgcheck=0

[HA-Add-On]
name=HA-Add-On
baseurl=file:///data/rhel7_repo/addons/HighAvailability
enabled=1
gpgcheck=0

[RS-Add-On]
name=RS-Add-On
baseurl=file:///data/rhel7_repo/addons/ResilientStorage
enabled=1
gpgcheck=0


yum repolist
[...]
repo id                        repo name                          status
HA-Add-On                      HA-Add-On                              25
RS-Add-On                      RS-Add-On                              57
localrhel7                     RHEL7_Base                          4,371
[...]

==========================================================
#########Need to recreate /etc/yum.repolist.d/ repositories for Centos8

[root@centos8 ~]# mkdir /tmp-repo
[root@centos8 ~]# rpm -qf /etc/yum.repos.d/CentOS-Base.repo
centos-repos-8.1-1.1911.0.8.el8.x86_64
[root@centos8 ~]# cd /tmp-repo/
[root@centos8 tmp-repo]# pwd
/tmp-repo
[root@centos8 tmp-repo]# rpm2cpio /media/BaseOS/Packages/centos-repos-8.1-1.1911.0.8.el8.x86_64.rpm | cpio --extract --make-directories --verbose "*.repo"
./etc/yum.repos.d/CentOS-AppStream.repo
./etc/yum.repos.d/CentOS-Base.repo
./etc/yum.repos.d/CentOS-CR.repo
./etc/yum.repos.d/CentOS-Debuginfo.repo
./etc/yum.repos.d/CentOS-Extras.repo
./etc/yum.repos.d/CentOS-HA.repo
./etc/yum.repos.d/CentOS-Media.repo
./etc/yum.repos.d/CentOS-PowerTools.repo
./etc/yum.repos.d/CentOS-Sources.repo
./etc/yum.repos.d/CentOS-Vault.repo
./etc/yum.repos.d/CentOS-centosplus.repo
./etc/yum.repos.d/CentOS-fasttrack.repo
22 blocks
[root@centos8 tmp-repo]# ls
etc
[root@centos8 tmp-repo]# cd etc/yum.repos.d/
[root@centos8 yum.repos.d]# ls
CentOS-AppStream.repo  CentOS-centosplus.repo  CentOS-Debuginfo.repo  CentOS-fasttrack.repo  CentOS-Media.repo       CentOS-Sources.repo
CentOS-Base.repo       CentOS-CR.repo          CentOS-Extras.repo     CentOS-HA.repo         CentOS-PowerTools.repo  CentOS-Vault.repo


=========================================================================================================================================================================
=========================================================================================================================================================================
########################## How to disable IPv6 on RHEL 8 / CentOS 8 step by step instructions:  #####################

# temporarily disable IPv6 address execute the following command from your terminal with administrative privileges:
$ sysctl -w net.ipv6.conf.all.disable_ipv6=1

# Confirm that IPv6 network addresses are disabled. Run the ip command and check for any inet6 IP address allocations:
$ ip a 

#Permanently disable IPv6 network address allocations by modifying the GRUB boot menu. First obtain the current kernelopts argument list: For example:
[root@HDB00 ~]# grub2-editenv - list | grep kernelopts
kernelopts=root=/dev/mapper/rootvg-root ro resume=/dev/mapper/rootvg-swap rd.lvm.lv=rootvg/root rd.lvm.lv=rootvg/swap rhgb quiet 
[root@HDB00 ~]#

#Next, append a new argument ipv6.disable=1 to the previously received kernelopts argument list: For example:
[root@HDB00 ~]# grub2-editenv - set "kernelopts=root=/dev/mapper/rootvg-root ro resume=/dev/mapper/rootvg-swap rd.lvm.lv=rootvg/root rd.lvm.lv=rootvg/swap rhgb quiet ipv6.disable=1"
[root@HDB00 ~]# reboot 

#Reboot your system to apply changes. Alternatively simply disable IPv6 as per

-------------
# In case you need to re-enable the IPv6 address execute:
$ sysctl -w net.ipv6.conf.all.disable_ipv6=0

If you have also modified GRUB boot to disable IPv6 as per above instructions use the grub2-editenv command to remove the ipv6.disable=1 argument.


=========================================================================================================================================================================
=========================================================================================================================================================================
######################################## First Way Strong Password RHEL 8  ##################################################
'####   pam_pwquality.so OR pam_cracklib

The pam_pwquality module is used to check a password's' strength against a set of rules. 
Its procedure consists of two steps: first it checks if the provided password is found in a dictionary.
 If not, it continues with a number of additional checks. 
 pam_pwquality is stacked alongside other PAM modules in the password component of the /etc/pam.d/passwd file, 
 and the custom set of rules is specified in the /etc/security/pwquality.conf configuration file. 
 For a complete list of these checks, see the pwquality.conf (8) manual page.


# Example 4.1. Configuring password strength-checking in pwquality.conf

1- To enable using pam_quality, add the following line to the password stack in the /etc/pam.d/passwd file:

password    required    pam_pwquality.so retry=3

2-
Options for the checks are specified one per line. For example, to require a password with a minimum length of 8 characters, including all four classes of characters, 
add the following lines to the /etc/security/pwquality.conf file

minlen = 8
minclass = 4

Set a password policy in Red Hat Enterprise Linux 

Requirement 2: minlen = 9 ( Minimum length of a password)
Insert the following option in /etc/security/pwquality.conf:
Raw
minlen = 8

Requirement 3: dcredit = -1 (Minimum credit for having required digits in password).
Insert the following option in /etc/security/pwquality.conf:
Raw
dcredit = -2

Requirement 4: ucredit = -1 ( Minimum credit for having uppercase characters in password )
Insert the following option in /etc/security/pwquality.conf:
Raw
ucredit = -2

 Requirement 5: lcredit = 1 ( Maximum credit for having lowercase characters in password )
Insert the following option in /etc/security/pwquality.conf:
Raw
lcredit = -2

Requirement 6: ocredit = 1 ( Maximum credit for having other characters in password )
Insert the following option in /etc/security/pwquality.conf:
Raw
ocredit = -1      




3-
To set a password strength-check for character sequences and same consecutive characters, add the following lines to /etc/security/pwquality.conf:
maxsequence = 3
maxrepeat = 3

NOTE: In this example, the password entered cannot contain more than 3 characters in a monotonic sequence, such as abcd, and more than 3 identical consecutive characters, such as 1111.

4-
Password aging is another technique used by system administrators to defend against bad passwords within an organization. Password aging means that after a specified period (usually 90 days), the user is prompted to create a new password. The theory behind this is that if a user is forced to change his password periodically, a cracked password is only useful to an intruder for a limited amount of time. The downside to password aging, however, is that users are more likely to write their passwords down

To specify password aging under Red Hat Enterprise Linux 7, make use of the chage command.

The -M option of the chage command specifies the maximum number of days the password is valid. For example, to set a user's' password to expire in 90 days, use the following command:
chage -M 90 username

To disable password expiration, use the value of -1 after the -M option.

chage -M -1  root

'
-d days Specifies the number of days since January 1, 1970 the password was changed.
-E date Specifies the date on which the account is locked, in the format YYYY-MM-DD. Instead of the date, the number of days since January 1, 1970 can also be used.
-I days Specifies the number of inactive days after the password expiration before locking the account. If the value is 0, the account is not locked after the password expires.
-l  Lists current account aging settings.
-m days Specify the minimum number of days after which the user must change passwords. If the value is 0, the password does not expire.
-M days Specify the maximum number of days for which the password is valid. When the number of days specified by this option plus the number of days specified with the -d option is less than the current day, the user must change passwords before using the account.
-W days Specifies the number of days before the password expiration date to warn the user.
'
The following is a sample interactive session using this command:
~]# chage juan
'
Changing the aging information for juan
Enter the new value, or press ENTER for the default
Minimum Password Age [0]: 10
Maximum Password Age [99999]: 90
Last Password Change (YYYY-MM-DD) [2006-08-18]:
Password Expiration Warning [7]:
Password Inactive [-1]:
Account Expiration Date (YYYY-MM-DD) [1969-12-31]:
'

Let’s now set a password policy to require a new password every 90 days.

sudo chage -M 90 user1

----------------
Exercise 4: Lock & Unlock user account
Locking the account prevents the user from authenticating with a password to the system. The usermod command can be used to lock an account with the -L option.

sudo usermod -L user1
Confirm:

$ su - user1
Password: 
su: Authentication failure
The account can later be unlocked with usermod -U command option.

sudo usermod -U user1

--------------------------------
sudo vim /etc/login.defs
Set PASS_MAX_DAYS to 40.

PASS_MAX_DAYS   40

'Note that the above-configured policy will only apply on the newly created users. To apply this policy to an existing user, use “chage” command.

To use chage command, syntax is:

$ chage [options] username'
To configure the maximum No. of days after which a user should change the password.

$ sudo chage -M <No./_of_days> <user_name>
To configure the minimum No. of days required between the change of password.

$ sudo chage -m <No._of_days> <user_name>
To configure warning prior to password expiration:

$ sudo chage -W <No._of_days> <user_name>


============================================
5-
 Account Locking
In Red Hat Enterprise Linux 7, the pam_faillock PAM module allows system administrators to lock out user accounts after a specified number of failed attempts. Limiting user login attempts serves mainly as a security measure that aims to prevent possible brute force attacks targeted to obtain a user's' account password.
With the pam_faillock module, failed login attempts are stored in a separate file for each user in the /var/run/faillock directory.
To lock out any non-root user after three unsuccessful attempts and unlock that user after 10 minutes, add two lines to the auth section of the 
/etc/pam.d/system-auth and /etc/pam.d/password-auth files. After your edits, the entire auth section in both files should look like this:

'
1 auth        required      pam_env.so
2 auth        required      pam_faillock.so preauth silent audit deny=3 unlock_time=600
3 auth        sufficient    pam_unix.so nullok try_first_pass
4 auth        [default=die] pam_faillock.so authfail audit deny=3 unlock_time=600
5 auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
6 auth        required      pam_deny.so
'
Lines number 2 and 4 have been added.

# Add the following line to the account section of both files specified in the previous step:
account     required      pam_faillock.so

OPTION:
'
To apply account locking for the root user as well, add the even_deny_root option to the pam_faillock entries in the /etc/pam.d/system-auth and /etc/pam.d/password-auth files:
auth        required      pam_faillock.so preauth silent audit deny=3 even_deny_root unlock_time=600
auth        sufficient    pam_unix.so nullok try_first_pass
auth        [default=die] pam_faillock.so authfail audit deny=3 even_deny_root unlock_time=600

account     required      pam_faillock.so
'
Example:
When the user john attempts to log in for the fourth time after failing to log in three times previously, his account is locked upon the fourth attempt:
~]$ su - john
Account locked due to 3 failed logins
su: incorrect password

OPTION:
To prevent the system from locking users out even after multiple failed logins, add the following line just above the line where pam_faillock is called for the first time in both /etc/pam.d/system-auth and /etc/pam.d/password-auth. Also replace user1, user2, and user3 with the actual user names.
auth [success=1 default=ignore] pam_succeed_if.so user in user1:user2:user3

To view the number of failed attempts per user, run, as root, the following command:
~]$ faillock
john:
When                Type  Source                                           Valid
2013-03-05 11:44:14 TTY   pts/0   

To unlock a user's' account, run, as root, the following command:
$ faillock --user <username> --reset

5-1
history not repeat password the times 3 
Requirement 1. Keep history of used passwords (the number of previous passwords which cannot be reused)
Insert the following in /etc/pam.d/system-auth and /etc/pam.d/password-auth (after pam_pwquality.so line):

password    requisite     pam_pwhistory.so remember=3 use_authtok



6-
Removing the nullok option
The nullok option, which allows users to log in with a blank password if the password field in the /etc/shadow file is empty, 
is enabled by default. To disable the nullok option, remove the nullok string from configuration files in the /etc/pam.d/ directory,
 such as /etc/pam.d/system-auth or /etc/pam.d/password-auth.

========================================================================================================================
#################################### Second Way Strong Password RHEL 8  ##################################################
# How to Configure Password Quality Rules {https://techdocs.broadcom.com/us/en/symantec-security-software/identity-security/directory/12-5/administrating/manage-user-accounts-and-passwords/create-a-password-policy/how-to-configure-password-quality-rules.html}

'Set Password Length
To set the length of new passwords, use one or both of these commands:'

$ set password-max-length = 0;
$ set password-min-length = 8;

'Set Minimum Numbers of Types of Characters
CA Directory includes commands that let you specify the minimum numbers of various types of characters that each new password must contain.
To set the minimum number of particular types or characters, use one or more of these commands:'

set password-policy = true

set password-alpha = 2;

set password-alpha-num = 2;

set password-lowercase = 1;

set password-non-alpha = 1;

set password-non-alpha-num = 1;

set password-numeric = 2;

set password-uppercase = 1;

'Limit Repetition of Characters
To limit repetition within the password, use the following command:'

'This lets you set the number of times a character can be repeated within a password.'
#set password-max-repetition = number-chars | 0 ;
set password-max-repetition = 2;

'To prevent users from reusing passwords, set the maximum number of passwords to retain in the history, using the following command:'

set password-history = 3;

'To prevent users from including their own names in the password, use the following command:'
set password-username-substring = true | false;
 
 'The user's name is taken to be the last RDN in their DN.'
 Example: Prevent Usernames in Passwords 
You have set up the following password policy in the Democorp DSA:'
set password-policy = true;
set password-username-substring = true;



#### Options:
'Limit Repetition of Substrings
You may want to prevent users from choosing passwords that consist of repetitions of the same strings, such as asdasdasd.
 Follow these steps: 
Set the minimum length of the substring that you want to check for, using the following command:'

set password-min-length-repeated-substring = length;

'alue for length is greater than or equal to 2;'
NOTE: This parameter above parameter functions only when password-max-substring-repetition is enabled.

'Set the number of times a substring can be repeated, using the following command:'
set password-max-substring-repetition = number-repetitions;

'You have set up the following password policy:'
set password-policy = true;
set password-max-substring-repetition = 1;
set password-min-length-repeated-substring = 3;

==========================================================================
######### third way password 
nano /etc/commom/passwd 
password  requisite      pam_pwquality.so   retry=3  minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1

OR
password        requisite pam_pwquality.so retry=4 minlen=9 difok=4 lcredit=-2 ucredit=-2 dcredit=-1 ocredit=-1 reject_username enforce_for_root


Note that
 the above-configured policy will only apply on the newly created users. To apply this policy to an existing user, use “chage” command.
'
===========================================================================================================================================================
#### allow users to TRANS 
/etc/pam.d/su
#%PAM-1.0
auth            sufficient      pam_rootok.so
auth  [success=ignore default=1] pam_succeed_if.so user = TRANS
auth  sufficient                 pam_succeed_if.so use_uid user ingroup osGroup
----------------------------------------------------------------------------
usermod -a -G osGroup cr1
usermod -a -G osGroup ch1
usermod -a -G osGroup tm1
usermod -a -G osGroup e07
usermod -a -G osGroup e08
usermod -a -G osGroup bg1
usermod -a -G osGroup db3
usermod -a -G osGroup e03
usermod -a -G osGroup e06
usermod -a -G osGroup ca2
usermod -a -G osGroup ch2
usermod -a -G osGroup c11
usermod -a -G osGroup c13
usermod -a -G osGroup tr1
usermod -a -G osGroup ch0
usermod -a -G osGroup c12
usermod -a -G osGroup c43
usermod -a -G osGroup rag
usermod -a -G osGroup c50
usermod -a -G osGroup c48
usermod -a -G osGroup c51

===========================================================================================================================================================
===========================================================================================================================================================
####################### How to configure rsh and rlogin on Red Hat Enterprise Linux
{https://access.redhat.com/articles/2980291}

Configure the rsh service on the server
1. Install the package

# yum -y install rsh-server

2. Configure the service to start at system boot
The rsh service is handled by systemd through the dedicated rsh socket.

# systemctl enable rsh.socket --now

3. Configure the dynamic firewall
The rsh service listens on the dedicated port 514/TCP.
The firewall must be configured to accept incoming connections to this port.

# firewall-cmd --permanent --add-port=514/tcp
# firewall-cmd --reload
'
Alternately, on Red Hat Linux Enterprise 7.3 and later, you may create a dedicated service as shown below:

Raw
# firewall-cmd --permanent --new-service=rsh-server
# firewall-cmd --permanent --service=rsh-server --set-description="rsh server"
# firewall-cmd --permanent --service=rsh-server --add-port=514/tcp
# firewall-cmd --permanent --add-service=rsh-server
# firewall-cmd --reload
'

Configure rsh on the client
1. Install the package
# yum -y install rsh

2. Configure the dynamic firewall
The rsh client, upon establishing a connection to the rsh server, uses dynamic TCP port allocation in the range 512:1023.
The firewall must be configured to accept incoming connections to these ports.

Raw
# firewall-cmd --permanent --add-port=512-1023/tcp
# firewall-cmd --reload
Alternately, on Red Hat Linux Enterprise 7.3 and later, you may create a dedicated service as shown below:

Raw'
# firewall-cmd --permanent --new-service=rsh-client
# firewall-cmd --permanent --service=rsh-client --set-description="rsh client"
# firewall-cmd --permanent --service=rsh-client --add-port=512-1023/tcp
# firewall-cmd --permanent --add-service=rsh-client
# firewall-cmd --reload

Configure the login service on the server
1. Install the package
Raw
# yum -y install rsh-server
2. Configure the service to start at system boot
The rlogin service is handled by systemd through the dedicated rlogin socket.

Raw
# systemctl enable rlogin.socket --now

3. Configure the dynamic firewall
The rlogin service listens on the dedicated port 513/TCP.
The firewall must be configured to accept incoming connections to this port.

Raw
# firewall-cmd --permanent --add-port=513/tcp
# firewall-cmd --reload
Alternately, on Red Hat Linux Enterprise 7.3 and later, you may create a dedicated service as shown below:

Raw
# firewall-cmd --permanent --new-service=rlogin-server
# firewall-cmd --permanent --service=rlogin-server --set-description="rlogin server"
# firewall-cmd --permanent --service=rlogin-server --add-port=513/tcp
# firewall-cmd --permanent --add-service=rlogin-server
# firewall-cmd --reload


[root@HDB00 asadmin]# firewall-cmd --list-all
'public (active)
  target: default
  icmp-block-inversion: no
  interfaces: ens32
  sources: 
  services: cockpit dhcpv6-client rlogin-server rsh-client rsh-server ssh telnet-server
  ports: 
  protocols: 
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
'

Configure rlogin on the client
1. Install the package
Raw
# yum -y install rsh

2. Configure the dynamic firewall
It is not necessary to configure the firewall.
-------------------------
# rsh.socket fails to start with IPv6 disabled
Red Hat Enterprise Linux 7
net.ipv6.conf.all.disable_ipv6 = 1 in /etc/sysctl.conf

systemctl status rsh.socket shows error Failed to listen on Remote Shell Facilities Activation Socket
Resolution
Using # dracut -v -f rebuild the initramfs to incorporate the changes made to /etc/sysctl.conf

===========================================================================================================================
===========================================================================================================================
###################################  How to enable the Telnet service
# rpm -qa | grep telnet
telnet-server-0.17-26.EL3.2
telnet-0.17-26.EL3.2
# if Not install
# yum install telnet-server telnet

Red Hat Enterprise Linux (RHEL) 7 and 8 Instructions
Add the service to firewalld:

Raw
$ firewall-cmd --permanent --add-service=rlogin-server
$ firewall-cmd --reload
OR 
# firewall-cmd --add-service=telnet --zone=public

Raw
# firewall-cmd --permanent --new-service=telnet-server
# firewall-cmd --permanent --service=telnet-server --set-description="telnet server"
# firewall-cmd --permanent --service=telnet-server --add-port=23/tcp
# firewall-cmd --permanent --add-service=telnet-server
# firewall-cmd --reload

Start and Enable the telnet service:

Raw
# systemctl start telnet.socket
# systemctl enable telnet.socket
or
# systemctl enable telnet.socket --now

Test the service:

Raw
# telnet server
Trying 1.1.1.1...
Connected to 1.1.1.1.
Escape character is '^]'.

Kernel 3.10.0-327.el7.x86_64 on an x86_64
server login: user
Password: 
Last login: Sat Jan 23 18:19:43 from other_server
[user@server ~]$ cat /etc/redhat-release
Red Hat Enterprise Linux Server release 7.2 (Maipo)

============================================================='
# yum list installed
# yum list packageName
# yum remove packageName

yum makecache fast
yum check-update

yum clean metadata
yum clean all 


-----------------------------
### Install package with download RPM
yum install --downloadonly --downloaddir=/root/mypackages/ httpd

=============================================================
#################### Error "su: Module is unknown" when try to su to root account
$ su -
Password: 
su: Module is unknown
Resolution
Correct the typo wrong module name in /etc/pam.d/system-auth.
Raw
From:

auth        required      sam_env.so

To:

auth        required      pam_env.so

============================================================================
SSHD configuration adjustment
If pam_faillock.so is not working as expected, the following changes may have to be made to SSHD's' configuration:

Raw
# vi /etc/ssh/sshd_config
ChallengeResponseAuthentication yes
PasswordAuthentication no
Then restart the sshd service in order for these configuration changes to take effect:

Raw
# systemctl restart sshd

if error sshd 
chown root:ssh_keys /etc/ssh/ecd*   
========================================================================
### Enable faillock.so 
 authconfig --enablefaillock --faillockargs="deny=3 unlock_time=600" --update

 Executing: /usr/bin/authselect check
Executing: /usr/bin/authselect select sssd with-faillock --force

===========================================================================
##### How to disable bluetooth in Red Hat Enterprise Linux?

Issue
Is there any way to disable bluetooth in Red Hat Enterprise Linux(RHEL) ?
Resolution
The Bluetooth kernel modules (bluetooth, bnep, btusb/hci_usb) are automatically loaded when the system boots and the Bluetooth service is enabled. The kernel modules can be prevented from being loaded by using system-wide modprobe rules.

Run the following commands to blocklist the Bluetooth modules, thus preventing them from loading if Bluetooth hardware is present:

On Red Hat Enterprise Linux 6, Red Hat Enterprise Linux 7 and Red Hat Enterprise Linux 8:

Raw
# echo "install bnep /bin/true" >> /etc/modprobe.d/disable-bluetooth.conf
​# echo "install bluetooth /bin/true" >> /etc/modprobe.d/disable-bluetooth.conf
​# echo "install btusb /bin/true" >> /etc/modprobe.d/disable-bluetooth.conf

Additionally, once the kernel modules are disabled, if you have the bluez (Bluetooth utilities) package installed you will want to have the Bluetooth service disabled at startup.
On Red Hat Enterprise Linux 7 or 8 execute the following commands as root:

Raw
# systemctl disable bluetooth.service
# systemctl mask bluetooth.service
# systemctl stop bluetooth.service

On Red Hat Enterprise Linux 6, Red Hat Enterprise Linux 7 and Red Hat Enterprise Linux 8 :

Raw
# rmmod bnep
# rmmod bluetooth
# rmmod btusb

================================================================================================
#### Login Last logins
he /var/log/lastlog file stores user last login information. 
This is binary file and act as database times of previous user logins. 
You need to use lastlog command to formats and prints the contents of the last login log /var/log/lastlog file.

$ lastlog
'
Sample outputs:

Username         Port     From             Latest
root             tty1                      Thu Jan 25 15:23:50 +0530 2007
daemon                                     **Never logged in**
bin                                        **Never logged in**
sys                                        **Never logged in**
sync                                       **Never logged in**
vivek            tty1                      Sat Jan 27 22:10:36 +0530 2007


======================================================================================================
### Create partition sdk1_
[root@sasdb-pro ~]# parted -s /dev/sdb  mklabel  gpt
[root@sasdb-pro ~]# parted -s /dev/sdb unit mib mkpart primary 1 100%
[root@sasdb-pro ~]# parted -s /dev/sdb  set  1 lvm on

### Create partition sdj1 512gb
[root@sasdb-pro ~]# parted -s /dev/sdj  mklabel  gpt
[root@sasdb-pro ~]# parted -s /dev/sdj unit mib mkpart primary 1 100%
[root@sasdb-pro ~]# parted -s /dev/sdj  set  1 lvm on


parted   
select /dev/sdc
print 


pvcreate /dev/sdj1
pvcreate /dev/sdk1

vgextend dbvg /dev/sdj1
vgextend dbvg /dev/sdk1


lvresize /dev/dbvg/dblv -l +100%FREE
   Size of logical volume dbvg/dblv changed from 2.44 TiB (639993 extents) to 3.44 TiB (902135 extents).
  Logical volume dbvg/dblv successfully resized.

-------------------------------
[root@t24-backup ~]# xfs_growfs /dev/dbvg/dblv 

========================================================================================
### Delete
 $ pvdisplay
 $ vgdisplay 
 $lvdisplay

 
[root@T24BKP ~]# umount  /backup

[root@T24BKP ~]#  lvchange -an /dev/t24vg/t24lv 

[root@T24BKP ~]# lvremove /dev/t24vg/t24lv
  Logical volume "t24lv" successfully removed

[root@T24BKP ~]# vgchange -an t24vg
  0 logical volume(s) in volume group "t24vg" now active

[root@T24BKP ~]# vgremove t24vg
  Volume group "t24vg" successfully removed

[root@T24BKP ~]# pvremove /dev/sdb1
sdb   sdb1  

[root@T24BKP ~]# pvremove /dev/sdb1
  Labels on physical volume "/dev/sdb1" successfully wiped
[root@T24BKP ~]# fdisk /dev/sdb1 # delete


======================================================================================
## Remove password for user 
passwd -d TRANS

------------------------------------------------------
Allow user1 to “su - user2” without password
============================================
 nmcli networking off && nmcli networking on

----
# ens192  internal host only
# ebs224  external NAT or bridge
$nmcli connection modify ens224 connection.zone internal 
$nmcli connection modify ens192 connection.zone external 

$firewall-cmd --get-zones
'inernal external'
$firwall-cmd --get-active-zones 
'external
   inetrface: ens192
 ineternal
   interface ens224
'
$firewall-cmd --zone-external --add-masquerade --permanent
$firewall-cmd --zone-inetrnal --add-masquerade --permanent
$firewall-cmd --list-all --zone=external

############################################ Network COnfiguration  #############################
To set up a network interface in Red Hat Enterprise Linux (RHEL) or CentOS via the command line, you can use tools like `nmcli` (NetworkManager command-line interface) or manually edit configuration files. Below are the steps for both methods:

---

### **Method 1: Using `nmcli` (Recommended for RHEL 7/8/9)**
`nmcli` is the modern way to manage networks in RHEL. It dynamically updates configurations and works with NetworkManager.

#### **Step 1: List Network Interfaces**
```bash
nmcli device status
# Or
ip a
```
Identify the interface name (e.g., `ens192`, `eth0`, `enp0s3`).

---

#### **Step 2: Configure the Interface**
**Option A: Set a Static IP Address**
```bash
sudo nmcli con add con-name "static-ens192" ifname ens192 type ethernet \
ip4 192.168.1.100/24 gw4 192.168.1.1
sudo nmcli con mod "static-ens192" ipv4.dns "8.8.8.8,8.8.4.4"
sudo nmcli con up "static-ens192"
```

**Option B: Use DHCP**
```bash
sudo nmcli con add con-name "dhcp-ens192" ifname ens192 type ethernet
sudo nmcli con up "dhcp-ens192"
```

---

#### **Step 3: Verify the Configuration**
```bash
ip a show ens192
ping google.com
```

---

### **Method 2: Manual Configuration via Config Files (RHEL 7/8/9)**
For systems where NetworkManager is disabled or deprecated (e.g., older setups).

#### **Step 1: Edit the Interface Config File**
Create or modify a configuration file for your interface in `/etc/sysconfig/network-scripts/`:
```bash
sudo vi /etc/sysconfig/network-scripts/ifcfg-ens192
```

**Static IP Configuration Example:**
```ini
DEVICE=ens192
BOOTPROTO=none
ONBOOT=yes
IPADDR=192.168.1.100
NETMASK=255.255.255.0
GATEWAY=192.168.1.1
DNS1=8.8.8.8
DNS2=8.8.4.4
TYPE=Ethernet
```

**DHCP Configuration Example:**
```ini
DEVICE=ens192
BOOTPROTO=dhcp
ONBOOT=yes
TYPE=Ethernet
```

---

#### **Step 2: Restart the Network Service**
```bash
# For RHEL 7:
sudo systemctl restart network

# For RHEL 8/9:
sudo nmcli connection reload
sudo nmcli connection down "ens192" && sudo nmcli connection up "ens192"
```

---

### **Method 3: Using `nmtui` (Text-Based UI)**
For a user-friendly interface:
```bash
sudo nmtui
```
Navigate to **Edit a connection** > Select your interface > Configure IP/DNS/Gateway > Save and exit.

---

### **Key Notes**
1. **Interface Naming:**
   - Modern RHEL uses predictable interface names like `ens192` or `enp0s3`.
   - Legacy names like `eth0` can be enabled by editing `/etc/default/grub` and regenerating the GRUB config.

2. **Persistent Configuration:**
   - Changes via `nmcli` or config files persist across reboots.
   - Temporary changes can be made with `ip addr add`, but they are lost on reboot.

3. **Check Connectivity:**
   ```bash
   ping 8.8.8.8         # Test internet connectivity
   ip route show        # Verify the default gateway
   systemctl status NetworkManager  # Check NetworkManager status
   ```

---

### **Troubleshooting**
- **Interface Not Found:** Ensure the interface is enabled in the kernel (`dmesg | grep eth`).
- **DNS Issues:** Verify `/etc/resolv.conf` has the correct DNS servers.
- **Firewall:** Check if firewalld or SELinux is blocking traffic:
  ```bash
  sudo systemctl stop firewalld   # Temporarily disable firewall
  sudo setenforce 0               # Temporarily disable SELinux
  ```

By following these steps, you can configure network interfaces in RHEL/CentOS efficiently. Use `nmcli` for modern systems or manual config files for legacy setups.




##################################################################################################
===============================================
 cd "/storage/"
for j in `cat users.txt |awk -F: '{print $1}'`
    do
       echo "usermod -a -G osGroup  "$j >> user-mod.txt
    done

===================================================='
### Upgrade branches for working DNS
add:
DNS1=172.17.15.35
DNS2=172.30.15.35
DOMAIN=hdb.local 

reboot network 

NOTE: copy hosts and remove all records

nameserver 172.17.15.35
nameserver 172.30.15.35
search hdb.local 
=================================================
I solved the problem "Entering emergency mode. Exit the shell to continue."
by using this command:
" xfs_repair -v -L /dev/dm-0"
then after Ctrl-Alt-Delete, my centos7 booted normally as usual.

========================================================================================================================
========================================================================================================================
###################################################3STEPS TO CONFIGURE LACP BONDING ON RHEL OR CENTOS 6 BY USING THE CLI TOOL
Backup the existing interfaces before you configure the bonding. Bring $slave1 and $slave2 down and move these files to a backup directory by using the following commands:

 ~]# ifdown p5p1 ; ifdown p5p2
 ~]#cd /etc/sysconfig/network-scripts
 ~]#mv -v ifcfg-p5p1 ifcfg-p5p2 ~/BACKUPDIR
Make sure module bonding is loaded by using the following command. You can also load the module with the command #modprobe bonding.

 ~]# lsmod |grep -i bonding
 bonding               145728  0
Create the file ifcfg-bond1 and modify the configuration by using the following commands:

~]#cd /etc/sysconfig/network-scripts
~]#cat ifcfg-bond1
DEVICE=bond1
TYPE=Ethernet
ONBOOT=yes
USERCTL=no
NM_CONTROLLED=no
MTU=9000
BOOTPROTO=static
IPADDR=179.254.0.2
PREFIX=16
DNS1=<DNS_IP>
BONDING_OPTS="mode=802.3ad miimon=100 lacp_rate=fast xmit_hash_policy=layer2+3"
Modify the slave interface (slave1 and slave2) configurations by using the following commands:

~]#cat ifcfg-p5p1
DEVICE=p5p1
BOOTPROTO=none
ONBOOT=yes
SLAVE=yes
USERCTL=no
NM_CONTROLLED=no
MASTER=bond1

~]#cat ifcfg-p5p2
DEVICE=p5p2
BOOTPROTO=none
ONBOOT=yes
SLAVE=yes
USERCTL=no
NM_CONTROLLED=no
MASTER=bond1
Restart the network or restart the server by using one of the following commands:

~]# service network restart

or

~]# init 6
After the service or server restart, check the proc for a bond interface by using the following command:

~]# cat /proc/net/bonding/bond0
Ethernet Channel Bonding Driver: v3.7.1 (April 27, 2011)

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
Transmit Hash Policy: layer2+3 (2)
MII Status: up
MII Polling Interval (ms): 100
Up Delay (ms): 0
Down Delay (ms): 0

802.3ad info
LACP rate: fast
Min links: 0
Aggregator selection policy (ad_select): stable
Active Aggregator Info:
  Aggregator ID: 1
  Number of ports: 1
  Actor Key: 9
  Partner Key: 550
  Partner Mac Address: 00:24:04:ef:bc:76

Slave Interface: p5p1
MII Status: up
Speed: 1000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: b4:b5:3f:8d:53:77
Aggregator ID: 1
Slave queue ID: 0

Slave Interface: p5p2
MII Status: up
Speed: 1000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: b4:b4:2f:5e:55:7b
Aggregator ID: 2
Slave queue ID: 0
Execute ifconfig -a and check that your bond1 interface is active.

=============================================================================================================================
============================================================================================================================
### Eroro in partiotion table 
lsblk
'
NAME           MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
fd0              2:0    1    4K  0 disk 
sda              8:0    0   16G  0 disk 
|-sda1           8:1    0  500M  0 part /boot
|-sda2           8:2    0 13.9G  0 part /
`-sda3           8:3    0  1.6G  0 part [SWAP]
sdb              8:16   0   20G  0 disk 
`-hdb_vg-home1 253:0    0   20G  0 lvm  /opt/disk2
sdc              8:32   0   20G  0 disk 
`-sdc1           8:33   0   20G  0 part#################Error not assing mount 
sr0             11:0    1 1024M  0 rom  
'

# parted /dev/sdb
GNU Parted 2.1
Using /dev/sdc 
Welcome to GNU Parted! Type 'help' to view a list of commands.
(parted) rescue 0% 100%
searching for file systems... 11%       (time left 03:29) 

$ lsblk
'
NAME           MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
fd0              2:0    1    4K  0 disk 
sda              8:0    0   16G  0 disk 
|-sda1           8:1    0  500M  0 part /boot
|-sda2           8:2    0 13.9G  0 part /
`-sda3           8:3    0  1.6G  0 part [SWAP]
sdb              8:16   0   20G  0 disk 
`-hdb_vg-home1 253:0    0   20G  0 lvm  /opt/disk2
sdc              8:32   0   20G  0 disk 
`-sdc1           8:33   0   20G  0 part /home
sr0             11:0    1 1024M  0 rom  
'
==========================================================================
############ ATM ###################
in ATM uf appear message not mount 
1- start HACM smit hacmp on two nodes 
2- fsck -y /dev/datalv

=====================================================
echo 'export HISTTIMEFORMAT="%d/%m/%y %T "' >> ~/.bash_profile
'
============================================================
### erase and install kernel-tool version:
yum update --allowerasing kernel-tools-libs-4.18.0-277.el8.x86_64.rpm
----------------
### Update kernel on redhat 7.7 from 3.10  5.4
yum install kernel*
'
kernel-5.4.96-200.el7.x86_64.rpm                       
kernel-core-5.4.96-200.el7.x86_64.rpm                  
kernel-cross-headers-5.4.96-200.el7.x86_64.rpm         
kernel-debug-5.4.96-200.el7.x86_64.rpm                 
kernel-debug-core-5.4.96-200.el7.x86_64.rpm            
kernel-debug-devel-5.4.96-200.el7.x86_64.rpm           
kernel-debug-modules-5.4.96-200.el7.x86_64.rpm         
kernel-debug-modules-extra-5.4.96-200.el7.x86_64.rpm   
kernel-debug-modules-internal-5.4.96-200.el7.x86_64.rpm
kernel-devel-5.4.96-200.el7.x86_64.rpm                 
kernel-headers-5.4.96-200.el7.x86_64.rpm               
kernel-modules-5.4.96-200.el7.x86_64.rpm               
kernel-modules-extra-5.4.96-200.el7.x86_64.rpm         
kernel-modules-internal-5.4.96-200.el7.x86_64.rpm      
kernel-tools-5.4.96-200.el7.x86_64.rpm                 
kernel-tools-libs-5.4.96-200.el7.x86_64.rpm            
kernel-tools-libs-devel-5.4.96-200.el7.x86_64.rpm      

vi 
reboot 

# remove old kernel
rpm -qa | grep kernel 

yum remove kernel-headers-3.10.0-862.el7.x86_64 --nodeps  # because have more dependienes 
yum remove kernel-tools-libs-3.10.0-862.el7.x86_64
yum remove kernel-3.10.0-862.el7.x86_64

===============================================================================
####  assig sequence in kernel menu at startup:
Note: exit version kernel-240 and update kernel 277 but not appear

[root@hdb00 ~]# ls -l  /boot/vmlinuz-*
-rwxr-xr-x. 1 root root 9514352 Dec 17 12:46 /boot/vmlinuz-0-rescue-9110f1896e444280963902c7dc15d24d
-rwxr-xr-x. 1 root root 9514352 Sep 23 11:31 /boot/vmlinuz-4.18.0-240.el8.x86_64
[root@hdb00 ~]# grubby --default-kernel
/boot/vmlinuz-4.18.0-240.el8.x86_64
[root@hdb00 ~]# grubby --default-index
1
[root@hdb00 ~]# grubby --info /boot/vmlinuz-4.18.0-240.el8.x86_64
index=1
kernel="/boot/vmlinuz-4.18.0-240.el8.x86_64"
args="ro resume=/dev/mapper/rootvg-swap rd.lvm.lv=rootvg/root rd.lvm.lv=rootvg/swap rhgb quiet ipv6.disable=1"
root="/dev/mapper/rootvg-root"
initrd="/boot/initramfs-4.18.0-240.el8.x86_64.img"
title="Red Hat Enterprise Linux (4.18.0-240.el8.x86_64) 8.3 (Ootpa)"
id="9110f1896e444280963902c7dc15d24d-4.18.0-240.el8.x86_64"

[root@hdb00 ~]# grubby --set-default-index=0
The default is /boot/loader/entries/9110f1896e444280963902c7dc15d24d-4.18.0-277.el8.x86_64.conf with index 0 and kernel /boot/9110f1896e444280963902c7dc15d24d/4.18.0-277.el8.x86_64/linux
[root@hdb00 ~]# reboot 

[root@automation ~]# ssh 172.17.7.122
root@172.17.7.122's password: 
Last login: Mon Feb  8 11:22:09 2021 from 172.24.2.34
[root@hdb00 ~]# uname -a
Linux hdb00 4.18.0-277.el8.x86_64 #1 SMP Wed Feb 3 20:35:19 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
'
======================================================================================================
### How to Change the default kernel (boot from old kernel) in CentOS/RHEL 8

$ grubby --default-kernel
/boot/vmlinuz-4.18.0-147.0.3.el8_1.x86_64

# Every kernel installed in the system has an index associated with it. To view the kernel index use:

$ grubby --default-index
0

# ls -l /boot/vmlinuz-*
-rwxr-xr-x. 1 root root 7872864 Apr 26  2019 /boot/vmlinuz-0-rescue-d026443091424a74948f9f62d2adb9b5
-rwxr-xr-x. 1 root root 7868768 Jun 19  2019 /boot/vmlinuz-0-rescue-ec2b9a54dc859388d7bc348e87df5332
-rwxr-xr-x. 1 root root 8106848 Nov 11 13:07 /boot/vmlinuz-4.18.0-147.0.3.el8_1.x86_64
-rwxr-xr-x. 1 root root 7876960 Sep 15  2019 /boot/vmlinuz-4.18.0-80.11.2.el8_0.x86_64
-rwxr-xr-x. 1 root root 7881056 Jul 26  2019 /boot/vmlinuz-4.18.0-80.7.2.el8_0.x86_64

# grubby --info /boot/vmlinuz-4.18.0-80.11.2.el8_0.x86_64
index=1
kernel="/boot/vmlinuz-4.18.0-80.11.2.el8_0.x86_64"
args="ro console=ttyS0,115200n8 console=tty0 net.ifnames=0 rd.blacklist=nouveau crashkernel=auto $tuned_params"
root="UUID=58013e4a-11c0-4195-8fd8-e4b33e5b17d6"
initrd="/boot/initramfs-4.18.0-80.11.2.el8_0.x86_64.img $tuned_initrd"
title="Red Hat Enterprise Linux (4.18.0-80.11.2.el8_0.x86_64) 8.0 (Ootpa)"
id="ec2b9a54dc859388d7bc348e87df5332-4.18.0-80.11.2.el8_0.x86_64"


# ls -l /boot/vmlinuz-*
-rwxr-xr-x. 1 root root 7872864 Apr 26  2019 /boot/vmlinuz-0-rescue-d026443091424a74948f9f62d2adb9b5
-rwxr-xr-x. 1 root root 7868768 Jun 19  2019 /boot/vmlinuz-0-rescue-ec2b9a54dc859388d7bc348e87df5332
-rwxr-xr-x. 1 root root 8106848 Nov 11 13:07 /boot/vmlinuz-4.18.0-147.0.3.el8_1.x86_64
-rwxr-xr-x. 1 root root 7876960 Sep 15  2019 /boot/vmlinuz-4.18.0-80.11.2.el8_0.x86_64
-rwxr-xr-x. 1 root root 7881056 Jul 26  2019 /boot/vmlinuz-4.18.0-80.7.2.el8_0.x86_64

2. Use the grubby command once you have devcided on which kernel to boot from:

# grubby --set-default [kernel-filename]
For example:

# grubby --set-default boot/vmlinuz-4.18.0-80.11.2.el8_0.x86_64

1. List out the available kernel filenames available in your system:

# ls -l /boot/vmlinuz-*
-rwxr-xr-x. 1 root root 7872864 Apr 26  2019 /boot/vmlinuz-0-rescue-d026443091424a74948f9f62d2adb9b5
-rwxr-xr-x. 1 root root 7868768 Jun 19  2019 /boot/vmlinuz-0-rescue-ec2b9a54dc859388d7bc348e87df5332
-rwxr-xr-x. 1 root root 8106848 Nov 11 13:07 /boot/vmlinuz-4.18.0-147.0.3.el8_1.x86_64
-rwxr-xr-x. 1 root root 7876960 Sep 15  2019 /boot/vmlinuz-4.18.0-80.11.2.el8_0.x86_64
-rwxr-xr-x. 1 root root 7881056 Jul 26  2019 /boot/vmlinuz-4.18.0-80.7.2.el8_0.x86_64
2. To view the index of any of the kernel listed above:

# grubby --info [kernel-filename] | grep index
For example:

# grubby --info /boot/vmlinuz-4.18.0-80.11.2.el8_0.x86_64 | grep index
index=1
3. Now that you know index of the kernel you want to boot from, use the command:

# grubby --set-default-index=[kernel-entry-index]
For example:

# grubby --set-default-index=1

#################################################
grubby --default-kernel
uname -r
grubby --info=ALL | grep ^kernel

grubby --set-default /boot/vmlinuz-5.14.0-70.13.1.el9_0.x86_64


yum remove kernel-10.2.22...x86_64

grub2-mkconfig -o /boot/grub2/grub.cfg 


=======================================================================================

########### To temporarily disable TCP timestamps for testing purposes

Add the following line to /etc/sysctl.d/tcp_timestamps.conf
net.ipv4.tcp_timestamps = 0

To do that, use the following command.
echo "net.ipv4.tcp_timestamps = 0" > /etc/sysctl.d/tcp_timestamps.conf

To apply the sysctl settings without a reboot, run the following command.

sysctl -p /etc/sysctl.d/tcp_timestamps.conf

Check if the changes have been properly set.
sysctl -a

If it worked correctly, the system should provide the following output.
net.ipv4.tcp_timestamps = 0

==============================================================
[root@server1 ~]# localectl list-locales
[root@server1 ~]# locale -a

 [root@server1 ~]#  localectl set-locale ar_IQ.iso88596

===========================================================
#### Server 84 :
#### Server 84  vmware tool not install
VMware Tools 10.3.22 build- "15902021" for Linux will not install on the operating
Solve :
For RHEL, that means open-vm-tools for all RHEL 7.x and newer, and vmware-tools for 5.x and 6.x.
root@HDB84# yum install open-vm-tools-11.0.5-3.el7_9.1.x86_64.rpm

with redhat iso repo 7.9

=============================================================================
We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things: 

#1) Respect the privacy of others.
#2) Think before you type.
#3) With great power comes great responsibility.

chown root:root /var/db/sudo/lectured
chmod 700 /var/db/sudo/lectured
chown -R root /var/db/sudo/lectured
cd into the folder and:

chmod 600 *

====================================================
[root@powervc opt]# yum makecache fast
Loaded plugins: product-id, search-disabled-repos, subscription-manager
This system is not registered with an entitlement server. You can use subscription-manager to register.
httpRepo                                                                                                                              | 2.9 kB  00:00:00     
httpRepo/primary_db                                                                                                                   | 5.1 MB  00:00:00     
Metadata Cache Created

===================================================================
root@localhost ~]# cpio -itv </mnt/ltfs/backup84.cpio  | grep savdata
---------------------------------------------------
===============================
### each login telnet operator with password 123 appear login incorrect:
vi /etc/pam.d/login 
#auth [user_unknown=ignore success=ok ignore=ignore default=bad] pam_securetty.so
vi /etc/pam.d/remote 
#auth       required     pam_securetty.so

restart telnet 

vi /etc/pam.d/rsh
#%PAM-1.0
# For root login to succeed here with pam_securetty, "rsh" must be
# listed in /etc/securetty.
#auth       required     pam_nologin.so
auth    sufficient      pam_nologin.so
#auth       required     pam_securetty.so
auth       sufficient     pam_securetty.so
#auth       required     pam_env.so
auth       sufficient     pam_env.so
#auth       required     pam_rhosts.so
auth       sufficient     pam_rhosts.so
account    include      password-auth
session    optional     pam_keyinit.so    force revokeet  
session    required     pam_loginuid.so
session    include      password-auth
~
------------------------------------------------------
######## How to confirm how many ports rsh connection uses
rexec 512
rlogin 513
rsh 514

rsh connetion will use ports randomly from 512 to 1023, so we need to permit these ports on firewall.

---------------------------
systemctl cat rsh.socket
# /usr/lib/systemd/system/rsh.socket
[Unit]
Description=Remote Shell Facilities Activation Socket

[Socket]
ListenStream=514
Accept=true

[Install]
WantedBy=sockets.target


=========================================================================================
# How to ignore ansible SSH authenticity checking?
vi /etc/ansible/ansible.cfg
[defaults]
host_key_checking = False
'
=======================================================
TRANS /home/waf/mdyon2102.txt hdb84:/tmp/

========================================================
### SSL on APache
yum install mod_ssl
vi /etc/https/config.d/ssl.config
'
Listen 443
NameVirtualHost  *:443

SSLProtocol  all -SSLv2 -SSLv3 

<VirtualHost *:443>
    sslEngine on 
  SSLCertificateFile /etc/pki/tls/certs/localhost.crt
    SSLCertificateKeyFile /etc/pki/tls/private/localhost.key
  Servername  www.example.com
  ServerAdmin    admin@example.com 
  DocumentRoot   /var/www/html/example.com/

</VirtualHost>
'
mkdir /var/www/html/example.com/
vi /var/www/html/example.com/index.html 
'
<h1>
   Welcome to my first SSL WebSite
</h1>
'

httpd -t 
service httpd restart 

vi /etc/hosts 
'
192.168.100.51     www.example.com
'


$ sudo apachectl start       [Start Apache web server]
$ sudo apachectl stop        [Stop Apache web server]
$ sudo apachectl restart     [Restart Apache web server]
$ sudo apachectl graceful    [Gracefully Restart Apache web server]
$ sudo apachectl configtest  [Check Apache Configuration]
$ sudo apachectl -V          [Check Apache Version]
$ sudo apachectl status      [Check Apache Status]

https://www.tecmint.com/check-apache-httpd-status-and-uptime-in-linux/

--------------------------------------------------
#####  Setting Up Virtual Hosts (Recommended)
on 119:
$ mkdir -p /data/cloud.me/rhel/8.3
$ mkdir -p /data/cloud.me/log  
$ chown -R apache:apache /data/cloud.me/
$ chmod -R 755 /data/cloud.me/

$ vi /data/cloud.me/index.html
'
<html>
  <head>
    <title>Welcome to Example.com!</title>
  </head>
  <body>
    <h1>Success! The example.com virtual host is working!</h1>
  </body>
</html>
'
$  mkdir /etc/httpd/sites-available /etc/httpd/sites-enabled

$ vi /etc/httpd/conf/httpd.conf
Add this line to the end of the file:
'
IncludeOptional sites-enabled/*.conf
'
$ vi /etc/httpd/sites-available/cloud.me.conf
'
<VirtualHost 172.250.1.119:80>
    ServerName www.cloud.me
    ServerAlias cloud.me 
    DocumentRoot /data/cloud.me/
    ErrorLog /data/cloud.me/log/error.log
    CustomLog /data/cloud.me/log/requests.log combined
</VirtualHost>
'
$ ln -s /etc/httpd/sites-available/cloud.me.conf /etc/httpd/sites-enabled/cloud.me.conf

# Add on Directory: 
$ vi  /etc/httpd/conf/httpd.conf
'
<Directory "/data/cloud.me">
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
'

#add IP in hosts andIP  www.cloud.me

$  httpd -t    test symtax  

=================================================================================
### Cups on legacy;
Unable to start CUPS Printing Service Sockets
Issue
I tried restarting inactive cups.socket service, but it is failing with below error:

Raw
systemd[1]: Socket service cups.service already active, refusing.
systemd[1]: Failed to listen on CUPS Printing Service Sockets.
Resolution
This message can be safely ignored.

Root Cause
The cups.socket service is intended to start cupsd whenever a process tries to open the Unix Domain socket /var/run/cups/cups.sock. CUPS commands such as lp, lpr, lpadmin, lpinfo, etc use this Unix Domain socket to communicate with the local CUPS service. However, if cupsd is already running, then cupsd will open /var/run/cups/cups.sock and listen for connections. What's happening in this case is that cupsd (started by cups.service) is already running, so when cups.socket tries to start, it sees that cupsd is already listening on /var/run/cups/cups.sock and emits a message to that effect.

'
 systemctl status cups.service cups.path cups.socket

[root@HDB00 ~]# systemctl list-units --all | grep cups                  
  cups.path                                                                                                      loaded    active   running   CUPS Scheduler                                                                              
  cups.service                                                                                                   loaded    active   running   CUPS Scheduler                                                                              
  cups.socket                                                                                                    loaded    inactive dead      CUPS Scheduler               
' 
======================================================
#### X11 Display GUI:
yum install xauth
yum install gtk*

vi /etc/ssh/sshd_config
'
AddressFamily inet
X11Forwarding yes
X11DisplayOffset 10
X11UseLocalhost yes

'
enable X11

login by each user by mobaXtem.
 xauth list

=================================================
Selinux awk :
To set SELinux to permissive, type the following command:
sed -i s/^SELINUX=.*$/SELINUX=permissive/ /etc/selinux/config


To set SELinux to disabled, type the following command:
sed -i s/^SELINUX=.*$/SELINUX=disabled/ /etc/selinux/config

setenforce 0

sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
============================================================
 Ensure that the default shell for your Linux operating system is /bin/bash. Use the following command to ensure that your default shell is bash and not dash:
$ readlink /bin/sh

====================================
############# Install Java 
# ls
ibm-java-x86_64-sdk-8.0-6.7.bin
For the installation step you need to login as user “root”.
The downloaded file is a “binary executable” file and thus, you need to ensure that it has
the proper “execute” permissions:
+++ROOT+++ fortin1.fyre.ibm.com: /
# cd /downloads/java
+++ROOT+++ fortin1.fyre.ibm.com: /downloads/java
# chmod 755 *.bin
# ls -l
total 162308
-rwxr-xr-x 1 root root 166200534 Apr 27 14:23 ibm-java-x86_64-sdk-8.0-6.7.bin

# ./ibm-java-x86_64-sdk-8.0-6.7.bin
Preparing to install...
Extracting the JRE from the installer archive...
Unpacking the JRE...
…
Choose Locale...
----------------
 1- Bahasa Indonesia
 2- Català
 3- Deutsch
 ->4- English
 5- Español
 6- Français
 7- Italiano
 8- Português
CHOOSE LOCALE BY NUMBER: 4
…
Press Enter to continue viewing the license agreement, or enter "1" to
 accept the agreement, "2" to decline it, "3" to print it, or "99" to go back
 to the previous screen.: 1
Respond to each prompt to proceed to the next step in the installation. If you
want to change something on a previous step, type 'back'.
You may cancel this installation at any time by typing 'quit'.
PRESS <ENTER> TO CONTINUE:
Choose Install Folder
---------------------
Where would you like to install?
 Default Install Folder: /opt/ibm/java-x86_64-80
ENTER AN ABSOLUTE PATH, OR PRESS <ENTER> TO ACCEPT THE DEFAULT
 :
Product Name:
 IBM® 64-bit SDK for Linux®, v8.0
Install Folder:
 /opt/ibm/java-x86_64-80
Disk Space Information (for Installation Target):

Required: 256,935,865 Bytes
 Available: 228,828,958,720 Bytes
PRESS <ENTER> TO CONTINUE:
Congratulations. IBM® 64-bit SDK for Linux®, v8.0 has been successfully
installed to:
 /opt/ibm/java-x86_64-80
PRESS <ENTER> TO EXIT THE INSTALLER:
Now let’s take a quick look at the default directory where the code was installed:
+++ROOT+++ fortin1.fyre.ibm.com: /downloads/java
# cd /opt/ibm/java-x86_64-80
# ls
bin demo include lib notices.txt release src.zip
copyright docs jre license_en.txt readme.txt sample _uninstall
# ls bin
appletviewer java javaw jdmpview policytool tnameserv
ControlPanel javac javaws jjs rmic unpack200
extcheck javadoc jconsole jrunscript rmid wsgen
idlj javah jcontrol keytool rmiregistry wsimport
jar javap jdb native2ascii schemagen xjc
jarsigner java-rmi.cgi jdeps pack200 serialver
# ls jre
bin lib plugin
# ls jre/bin
classic j9vm jcontrol keytool pack200 tnameserv
ControlPanel java jdmpview kinit policytool unpack200
ikeycmd javaw jextract klist rmid
ikeyman javaws jjs ktab rmiregistry

++ Setup of JAVA environment variables for the user “mqm”
Ok! So far, so good!
But what is next?
It is a good practice to create some environment variables inside the .bashrc (or .profile) in
order to facilitate the compilation and runtime tasks when using Java.
Login as user “mqm” (or another user who is going to use MQ Java/JMS)
Edit the .bashrc or similar profile script:
## Java Development Kit or Java Runtime Environment.
## Basic variables for Java
export JAVA_HOME=/opt/ibm/java-x86_64-80
export JAVA_BINDIR=$JAVA_HOME/bin
# Add Java to the PATH
export PATH=$JAVA_BINDIR:$PATH

==========================================
sudo dnf install java-11-openjdk-devel -y

sudo dnf install java-1.8.0-openjdk.x86_64 -y
==========================================================================
## Network:
TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
BOOTPROTO=none
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=no
NAME=ens32
UUID=62527652-6f08-4aeb-8417-b21a733e8716
DEVICE=ens32
ONBOOT=yes
IPADDR=172.30.7.200
PREFIX=24
GATEWAY=172.30.7.1
DNS1=172.30.15.35
DNS2=172.17.15.35
DOMAIN=hdb.local
IPV6_DISABLED=yes
ETHTOOL_OPTS="autoneg on"

===================================================================
### To sleep for 5 days, use: ##
sleep 5d

#Halt or sleep for 3 hours, use:
sleep 3h

#Want to sleep for 2 minutes, use:
sleep 2m

#To sleep for 5 seconds, use:
sleep 5

=========================================================
### Persmission deny on 47 by
 #user hd1 when run :
su - SSH -c "ssh SSH@hdb47 'runcobol' "

changed in sshd_config: under /data/sshd_config
'
# $OpenBSD: sshd_config,v 1.100 2016/08/15 12:32:04 naddy Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

# If you want to change the port on a SELinux system, you have to tell
# SELinux about this change.
# semanage port -a -t ssh_port_t -p tcp #PORTNUMBER
#
#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
SyslogFacility AUTHPRIV
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

PubkeyAuthentication no 

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile  .ssh/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
PermitEmptyPasswords yes 
PasswordAuthentication no 

# Change to no to disable s/key passwords
#ChallengeResponseAuthentication yes
ChallengeResponseAuthentication yes 

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no
#KerberosUseKuserok yes

# GSSAPI options
#GSSAPIAuthentication yes
#GSSAPICleanupCredentials no
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no
#GSSAPIEnablek5users no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
# WARNING: 'UsePAM no' is not supported in Red Hat Enterprise Linux and may cause several
# problems.
UsePAM yes 

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#UseLogin no
#UsePrivilegeSeparation sandbox
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#ShowPatchLevel no
#UseDNS yes
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Accept locale-related environment variables
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS

# override default of no subsystems
Subsystem sftp  /usr/libexec/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
# X11Forwarding no
# AllowTcpForwarding no
# PermitTTY no
# ForceCommand cvs server

------------------------------------------------------------------
#What is Causing SSH Permission Denied (publickey,gssapi-keyex,gssapi-with-mic)?

n the file, find the PasswordAuthentication line and make sure it ends with yes.

Find the ChallengeResponseAuthentication option and disable it by adding no.

If lines are commented out, remove the hash sign # to uncomment them.

======================================================================

### Create services:
vim /etc/systemd/system/xcs.service
'
[Unit]
Description = making XCS servcie running
After = xcs.target

[Service]
ExecStart = /home/WebAdmin/XCS/RenewalMigProcess/xcs.sh

[Install]
WantedBy = multi-user.target
'  
systemctl enable xcs.service

ls multi-user.target.wants/

/home/WebAdmin/XCS/RenewalMigProcess/xcs.sh
'
#!/bin/bash
sudo nohup java -jar /home/WebAdmin/XCS/RenewalMigProcess/RenewalMigProcess.jar &

'
systemctl start xcs.service

=============================================
#### Permissions 0644 for '/root/.ssh/id_rsa' are too open
chmod 400 ~/.ssh/id_rsa

'===========================================================================
=============================================================================
### Configure NTP server on Linux legacy:
#How to Configure NTP Client Using Chrony in RHEL 8
$  yum install chrony -y
systemctl start chronyd
systemctl enable chronyd
systemctl status chronyd

vi /etc/chrony.conf
'
# pool 2.rhel.pool.ntp.org iburs

server   ntp-hq.hdbank.local
server   ntp-dr.hdbank.local 
'
'
 server 0.africa.pool.ntp.org
 server 1.africa.pool.ntp.org
 server 2.africa.pool.ntp.org
server 3.africa.pool.ntp.org
'
-------------
nc -zvu ptbtime1.ptb.de 123
Connection to ptbtime1.ptb.de 123 port [udp/ntp] succeeded!


[root@studentvm1 ~]# chronyc tracking
Reference ID    : 23ABED4D (ec2-35-171-237-77.compute-1.amazonaws.com)
Stratum         : 3
Ref time (UTC)  : Fri Nov 16 16:21:30 2018
System time     : 0.000645622 seconds slow of NTP time
Last offset     : -0.000308577 seconds
RMS offset      : 0.000786140 seconds
Frequency       : 0.147 ppm slow
Residual freq   : -0.073 ppm
Skew            : 0.062 ppm
Root delay      : 0.041452706 seconds
Root dispersion : 0.022665167 seconds
Update interval : 1044.2 seconds
Leap status     : Normal
[root@studentvm1 ~]#
---------------
root@compute ~]# chronyc sources
210 Number of sources = 2
MS Name/IP address         Stratum Poll Reach LastRx Last sample               
===============================================================================
^* hdb-dc-pmain.hdbank.local     2   6    17    11    +32ms[  +37ms] +/-  121ms
^+ hdb-dc-pdr.hdbank.local       2   6    15    11    -55ms[ -3511s] +/-  203ms
-----------------------------------------
 chronyc sources -v
 -------------------------------------
 watch chronyc tracking


----------
[root@HDBA8 ~]# nslookup ntp-dr.hdbank.local
Server:         172.30.15.35
Address:        172.30.15.35#53

ntp-dr.hdbank.local     canonical name = hdb-dc-pdr.hdbank.local.
Name:   hdb-dc-pdr.hdbank.local
Address: 172.30.10.10

[root@HDBA8 ~]# nslookup ntp-hq.hdbank.local
Server:         172.30.15.35
Address:        172.30.15.35#53

ntp-hq.hdbank.local     canonical name = hdb-dc-pmain.hdbank.local.
Name:   hdb-dc-pmain.hdbank.local
Address: 172.17.10.10

###############
timedatectl list-timezones

#######################################################################
To set up Chrony on a Linux system for accurate time synchronization, follow these steps:

### 1. **Install Chrony**
Use your distribution's package manager to install Chrony:

- **Debian/Ubuntu**:
  ```bash
  sudo apt update && sudo apt install chrony
  ```

- **Red Hat/CentOS/Fedora**:
  ```bash
  sudo yum install chrony      # For CentOS 7/RHEL 7
  sudo dnf install chrony      # For CentOS 8+/Fedora
  ```

### 2. **Configure Chrony**
Edit the configuration file `/etc/chrony/chrony.conf` (or `/etc/chrony.conf` on some systems) to specify NTP servers:

```bash
sudo nano /etc/chrony/chrony.conf
```

- **Add/Update NTP Servers**:
  Replace the default `pool` entries with your preferred NTP servers (e.g., regional pools or internal servers):
  ```bash
  server 0.pool.ntp.org iburst
  server 1.pool.ntp.org iburst
  server 2.pool.ntp.org iburst
  server 3.pool.ntp.org iburst
  ```
  The `iburst` option speeds up initial synchronization.

- **Optional Settings**:
  - Allow manual time adjustments (e.g., for large time jumps):
    ```bash
    makestep 1.0 3
    ```
  - Configure logging (optional):
    ```bash
    logdir /var/log/chrony
    ```

### 3. **Start and Enable the Service**
Start Chrony and enable it to run at boot:

```bash
sudo systemctl restart chrony       # Restart the service
sudo systemctl enable chrony       # Enable on boot
```

### 4. **Verify Synchronization**
Check if Chrony is syncing with the configured servers:

```bash
chronyc tracking      # View system clock status
chronyc sources -v    # List time sources and their status
```

Example output:
```
MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^* time.cloudflare.com           3   6    17    36   +234us[ +512us] +/-   18ms
^+ ntp1.example.com              2   6    17    35   -145us[ -145us] +/-   25ms
```

### 5. **Firewall Configuration**
Allow NTP traffic (UDP port 123) if a firewall is active:

- **UFW (Ubuntu)**:
  ```bash
  sudo ufw allow 123/udp
  ```

- **Firewalld (RHEL/CentOS)**:
  ```bash
  sudo firewall-cmd --add-service=ntp --permanent
  sudo firewall-cmd --reload
  ```

### 6. **Force Immediate Sync (Optional)**
If the clock is significantly skewed, force an immediate adjustment (use cautiously):

```bash
sudo chronyc makestep
```

### 7. **Check System Time and Timezone**
Ensure the system timezone is correctly configured:

```bash
timedatectl                     # Check current time settings
sudo timedatectl set-timezone Region/City  #   # Set timezone (e.g., America/New_York)

sudo timedatectl set-ntp off
sudo timedatectl set-ntp on
```

### 8. **Troubleshooting**
- **View Logs**:
  ```bash
  sudo journalctl -u chrony      # Check Chrony service logs
  ```
- **Resync Manually**:
  ```bash
  sudo chronyc -a makestep
  ```

---

### Example Configuration File Snippet
```bash
# /etc/chrony/chrony.conf
server 0.pool.ntp.org iburst
server 1.pool.ntp.org iburst
server 2.pool.ntp.org iburst
server 3.pool.ntp.org iburst

# Allow large time corrections if needed
makestep 1.0 3

# Record rate of system clock gain/loss
driftfile /var/lib/chrony/drift

# Enable kernel synchronization
rtcsync

# Logging
logdir /var/log/chrony
```

---

By following these steps, your Linux system will maintain accurate time using Chrony. Adjust server entries and settings based on your network environment (e.g., internal NTP servers).






##########################################################################
===================================================
### Apply monitor users on legacy:{https://ostechnix.com/monitor-user-activity-linux/}
#How To Monitor User Activity In Linux
yum install psacct
systemctl enable psacct
systemctl start psacct
'
ac - Displays statistics about how long users have been logged on.
lastcomm - Displays information about previously executed commands.
accton - Turns process accounting on or off.
dump-acct - Transforms the output file from the accton format to a human-readable format.
dump-utmp - Prints utmp files in human-readable format.
sa - Summarizes information about previously executed commands.
'

The ac utility will display the report of connect time in hours. It can tell you how long a user or group of users were connected to the system.
$ ac 
$ ac -d
$ ac -p
$ ac sk
$ ac -d root

$ lastcomm
$ lastcomm sk
$ lastcomm  user-name hd1
$ lastcomm vi
$ man lastcomm

=====================================
### copy backup of logs on WAS on XCS 10.20.30.40.50.60

mdkir /WEBAPP/BkpWASLogs/

cp -p   /WEBAPP/XCS/WebSphere/AppServer/profiles/AppSrvr01/logs/XCSMember01/SystemOut.log  /WEBAPP/BkpWASLogs/VM_10_SystemOut_`date`.log
cp -p   /WEBAPP/XCS/WebSphere/AppServer/profiles/AppSrvr01/logs/XCSMember01/SystemErr.log  /WEBAPP/BkpWASLogs/VM_10_SystemErr_`date`.log

rsync ???   /WEBAPP/BkpWASLogs/*   172.17.77.250:/

==========================================================
yum install -y nc
### Test telnet UDP

TCP: 
# nc -z -v -u [hostname/IP address] [port number] 
 
# nc -z -v 192.168.10.12 22 
Connection to 192.118.20.95 22 port [tcp/ssh] succeeded! 

UDP:
# nc -z -v [hostname/IP address] [port number] 
 
# nc -z -v -u 192.168.10.12 123 
Connection to 192.118.20.95 123 port [udp/ntp] succeeded! 

===============================================
### umount xfs due to I/O error and not mount
$ mount /dev/dockervg/dockerlv 
 error 
$ xfs_repair  /dev/dockervg/dockerlv
if Error
$ xfs_repair  -L /dev/dockervg/dockerlv

===============================================
### mount flash
$ fdisk -l
'
Disk /dev/sdb: 15.7 GB, 15664676864 bytes
255 heads, 63 sectors/track, 1904 cylinders, total 30595072 sectors
Units = sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disk identifier: 0x00000000
Device Boot Start End Blocks Id System
/dev/sdb1 * 32 30595071 15297520 c W95 FAT32 (LBA)
'

$ mount /dev/sdb1 /mnt

==============================================================================
### Install Fireeye on linux: {https://umd.service-now.com/itsupport?id=kb_article&article=KB0015995&sys_kb_id=858afc10dbbe28106aa41517489619d1&spa=1}
rpm -ivh /home/xagt-33.46.0-1.el7.x86_64.rpm

mkdir /usr/bin/fireeye/
cp /home/agent_config.json /home/xagt-33.46.0-1.el7.x86_64.rpm   /usr/bin/fireeye/

#Initialize the agent with the config file: 
/opt/fireeye/bin/xagt -i  /usr/bin/fireeye/agent_config.json

'Success'

#Start the agent: 
sudo systemctl start xagt

#Set the agent to start on reboot: 
sudo systemctl enable xagt

# Verify install
ps -ef | grep xagt

'root     21414     1  1 15:34 ?        00:00:00 /opt/fireeye/bin/xagt -M DAEMON'

#You can verify the version running via the following command
[root@hdba6 ~]# /opt/fireeye/bin/xagt -v
v33.46.0
=======================================================================================
###Set the password to ‘hacluster’ user
echo <new-password> | passwd --stdin hacluster
================================================
lppchk 
'
The lppchk command verifies that files for an installable software product (fileset) match the Software Vital Product Data (SWVPD) database information for file sizes, checksum values, or symbolic links. A fileset is a separately installable option of a software package.
'
===================================================
######################## Install php on redhat 8 upgrade 221 ###################
{https://www.cyberciti.biz/faq/install-php-7-x-on-centos-8-for-nginx/}

sudo yum module list php
'
Name                   Stream                    Profiles                                     Summary                                
php                    7.2 [d]                   common [d], devel, minimal                   PHP scripting language                 
php                    7.3                       common [d], devel, minimal                   PHP scripting language                 
php                    7.4                       common [d], devel, minimal                   PHP scripting language  
Hint: [d]efault, [e]nabled, [x]disabled, [i]nstalled
'
sudo yum module reset php
sudo yum module enable php:7.4
## verify it php set to 7.4 ##
sudo yum module list php
'
http repository
Name                   Stream                    Profiles                                     Summary                                
php                    7.2 [d]                   common [d], devel, minimal                   PHP scripting language                 
php                    7.3                       common [d], devel, minimal                   PHP scripting language                 
php                    7.4 [e]                   common [d], devel, minimal                   PHP scripting language                 

Hint: [d]efault, [e]nabled, [x]disabled, [i]nstalled
'
yum install php php-fpm
php -v
'
PHP 7.4.6 (cli) (built: May 12 2020 08:09:15) ( NTS )
Copyright (c) The PHP Group
Zend Engine v3.4.0, Copyright (c) Zend Technologies
    with Zend OPcache v7.4.6, Copyright (c), by Zend Technologies
'
systemctl enable php-fpm.service

sudo systemctl start php-fpm.service
sudo systemctl status php-fpm.service

===================================
################## Install mysql on redhat 8 upgrsde 221 ##############
sudo dnf install mysql-server
sudo systemctl start mysqld.service
sudo systemctl status mysqld
sudo systemctl enable mysqld

[root@card-data-flow-db ~]# mysqladmin -u root -p version
Enter password: empty 
mysqladmin  Ver 8.0.21 for Linux on x86_64 (Source distribution)
Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Server version          8.0.21
Protocol version        10
Connection              Localhost via UNIX socket
UNIX socket             /var/lib/mysql/mysql.sock
Uptime:                 47 sec

Threads: 2  Questions: 2  Slow queries: 0  Opens: 118  Flush tables: 3  Open tables: 36  Queries per second avg: 0.042

=================================================================================================
##### Timestamp
[root@automation ~]#epoch=$(date -d "${orig}" +"%s")
[root@automation ~]# echo $epoch
1629172800

root@automation ~]# echo "1629172800" | gawk '{print strftime("%c",$1)}'
Tue 17 Aug 2021 12:00:00 AM EDT
[root@automation ~]# date
Tue Aug 17 09:37:50 EDT 2021

=============================================
{https://www.unixtimestamp.com/}
root@oracle-area # perl  /home/asadmin/timestamp.pl
1629165952
root@oracle-area # printf "%(%F %T)T\n" 1629165952
2021-08-17 04:05:52
root@oracle-area # date
Tue Aug 17 04:06:02 EET 2021

cat timestamp.pl 
'
#!/usr/bin/perl

# udate.pl - print seconds since "the epoch"

print scalar time, "\n";
'
=================================================================
### newtwok unreachable , with that network propally
$ route -n 
[root@hdba8 home]# cat /etc/sysconfig/network
NETWORKING=yes
HOSTNAME=hdba8
#GATEWAYDEV=eno16777984
GATEWAYDEV=ens160
GATEWAY=172.30.7.254

======================================================
Fix Failed to download metadata for repo
CentOS Linux 8 had reached the End Of Life (EOL) on December 31st, 2021

Step 1: Go to the /etc/yum.repos.d/ directory.
[root@autocontroller ~]# cd /etc/yum.repos.d/

[root@autocontroller ~]# sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*

[root@autocontroller ~]# sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

[root@autocontroller ~]# yum update -y
--------------------------------------------------------------
sed -i 's/127.0.0.1/192.168.56.101/g' *.xml 

=====================================================
### What is Causing SSH Permission Denied (publickey,gssapi-keyex,gssapi-with-mic)?
sudo nano /etc/ssh/sshd_config
'
PasswordAuthentication yes
ChallengeResponseAuthentication no 
'

=====================================================
### Disable IPv6 on cenos 8
ip a | grep inet6
vi /etc/sysctl.d/70-ipv6.conf
'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
'
sysctl --load /etc/sysctl.d/70-ipv6.conf
ip a | grep inet6
=================================================
### disable selinux by sed
sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config
cat /etc/selinux/config | grep SELINUX=
=======================================================
### Install AWX on Centos 8
# install ansible environemnt:
sudo yum install python3
sudo alternatives --set python /usr/bin/python3
python --version
sudo yum install python3-virtualenv
#In your Ansible-powered project, create virtualenv:

virtualenv venv
. venv/bin/activate
pip install ansible
#Now Ansible is safely installed to venv of your project. Whenever you need to run it, make sure to activate the virtual environment first, e.g.:

virtualenv venv
ansible --version

###############################
# Alternative java
update-alternatives --config java

# if using JAVA_HOME by manual install
unlink /etc/alternatives/java
ln -s /opt/jdk-21.0.4+7/bin/java /etc/alternatives/java

unlink /etc/alternatives/javac

ln -s /opt/jdk-21.0.4+7/bin/javac /etc/alternatives/javac


=======================================================
### Install Python 3.9 on Rocky Linux 8 / AlmaLinux 8
sudo dnf  -y update
sudo reboot
sudo dnf install python39
$ python3.9 --version
Python 3.9.7
-------------------------------
 ### Download and Install Python 3.9 Manually
sudo dnf groupinstall "Development Tools" -y
sudo dnf install openssl-devel libffi-devel bzip2-devel -y

$ gcc --version

## Download latest Python 3.9 Archive
Using wget command, download Python 3.9 latest release to install:

sudo dnf install wget -y
wget https://www.python.org/ftp/python/3.9.13/Python-3.9.13.tar.xz

tar xvf Python-3.9*.tar.xz
Change to the directory that was created during the file extraction:

cd Python-3.9*/


##Install Python 3.9 on Rocky Linux 8 / AlmaLinux 8
To setup Python installation, use the command below:

./configure --enable-optimizations

sudo make altinstall

$ python3.9 --version
Python 3.9.13

# OR
$ /usr/local/bin/python3.9 --version
Python 3.9.13

$ pip3.9 --version
pip 21.2.3 from /usr/local/lib/python3.9/site-packages/pip (python 3.9)


###Install Python 3.9 Modules on Rocky Linux 8 / AlmaLinux 8
python3.9 -m pip install <module>


------------------------------------------------------
{https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html}
### Ansible
python3.9 -m pip -V

#If you see an error like No module named pip
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3.9 get-pip.py --user


Installing Ansible:
python3.9 -m pip install --user ansible

#Alternately, you can install a specific version of ansible-core in this Python environment:

python3.9 -m pip install --user ansible-core==2.12.3


#Upgrading Ansible:

python3.9 -m pip install --upgrade --user ansible

ansible --version

python3.9 -m pip show ansible

============================================
### Installing devel from GitHub with pip

python3.9 -m pip install --user https://github.com/ansible/ansible/archive/devel.tar.gz

git clone https://github.com/ansible/ansible.git
cd ./ansible

## Setup the Ansible environment
source ./hacking/env-setup

#To suppress spurious warnings/errors, use -q

source ./hacking/env-setup -q

#Install Python dependencies

python3.9 -m pip install --user -r ./requirements.txt


## Update the devel branch of ansible-core on your local machine

Use pull-with-rebase so any local changes are replayed.

git pull --rebase

### Adding Ansible command shell completion:

python3.9 -m pip install --user argcomplete

##Configuring argcomplete:
There are 2 ways to configure argcomplete to allow shell completion of the Ansible command line utilities: globally or per command.

#Global configuration:
#Global completion requires bash 4.2.

$activate-global-python-argcomplete


##Per command configuration:
If you do not have bash 4.2, you must register each script independently.

eval $(register-python-argcomplete ansible)
eval $(register-python-argcomplete ansible-config)
eval $(register-python-argcomplete ansible-console)
eval $(register-python-argcomplete ansible-doc)
eval $(register-python-argcomplete ansible-galaxy)
eval $(register-python-argcomplete ansible-inventory)
eval $(register-python-argcomplete ansible-playbook)
eval $(register-python-argcomplete ansible-pull)
eval $(register-python-argcomplete ansible-vault)
`
============================================================

========================================================================================================
-------------------------------------------
sudo dnf install epel-release -y
sudo dnf install git gcc gcc-c++ ansible nodejs gettext device-mapper-persistent-data lvm2 bzip2 python3-pip -y
sudo dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf install docker-ce
systemctl start docker
systemctl enable docker

sudo dnf install python3-pip

pip3 install docker-compose
docker-compose --version
sudo alternatives --set python /usr/bin/python3
git clone -b "17.1.0" https://github.com/ansible/awx.git
openssl rand -base64 30
'AoMsqm/ZR0778rQO3fVQlnWf83E4owH8uRyQThuk'
vi /home/amsadmin/awx/installer/inventory 
'
dockerhub_base=ansible
awx_task_hostname=awx
awx_web_hostname=awxweb
postgres_data_dir="/var/lib/pgdocker"
host_port=80
host_port_ssl=443
docker_compose_dir="~/.awx/awxcompose"
pg_username=awx
pg_password=awxpass
pg_database=awx
pg_port=5432
pg_admin_password=password
rabbitmq_password=awxpass
rabbitmq_erlang_cookie=cookiemonster
admin_user=admin
admin_password=password
create_preload_data=True
secret_key=R+kbcDEUS8DlAftAbfWafVqLZ0lUy+Paqo4fEtgp
awx_official=true
awx_alternate_dns_servers="8.8.8.8,8.8.4.4"
project_data_dir=/var/lib/awx/projects
'
mkdir /var/lib/pgdocker

#########

curl -SL https://github.com/docker/compose/releases/download/v2.26.1/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose

=================================================================
## Recommended things to do after installing a Linux server to beef up the security

## ssh key generate
# Disable all SSH forwarding
DisableForwarding yes


## Disable password-based SSH authentication
PasswordAuthentication no

IgnoreRhosts yes

----------------
## Disable IPV6
## Add the following at the bottom of the file:

net.ipv6.conf.all.disable_ipv6 = 1

net.ipv6.conf.default.disable_ipv6 = 1

net.ipv6.conf.lo.disable_ipv6 = 1

4. Save and close the file.

5. Reboot the machine.

To re-enable IPv6, remove the above lines from /etc/sysctl.conf and reboot the machine.
------------------
change hosts file and add ipv4 and host it.
--------------
NTP protocol
----------
Add Network and DNS.
====================================================================================================================================
# ressolv.conf
nameserver 127.0.0.53
options edns0 trust-ad
----------------------------------------------------
## PATH
export PATH=/var/lib/rancher/rke2/bin:$PATH
=========================================================
### Nested virtualization
[root@kvm-hypervisor ~]# cat /sys/module/kvm_intel/parameters/nested
N
[root@kvm-hypervisor ~]#
[root@kvm-hypervisor ~]# cat /sys/module/kvm_amd/parameters/nested
N
[root@kvm-hypervisor ~]#

[root@kvm-hypervisor ~]# vi /etc/modprobe.d/kvm-nested.conf
options kvm-intel nested=1
options kvm-intel enable_shadow_vmcs=1
options kvm-intel enable_apicv=1
options kvm-intel ept=1

[root@kvm-hypervisor ~]# modprobe -r kvm_intel
[root@kvm-hypervisor ~]# modprobe -a kvm_intel
[root@kvm-hypervisor ~]#

[root@kvm-hypervisor ~]# cat /sys/module/kvm_intel/parameters/nested
Y
[root@kvm-hypervisor ~]


[root@director ~]# lsmod | grep kvm
kvm_intel             170200  0
kvm                   566604  1 kvm_intel
irqbypass              13503  1 kvm
[root@director ~]#
[root@director ~]# lscpu

#################################################################
### KVM
sudo dnf install -y libvirt virt-manager virt-install virt-viewer libvirt-client qemu-kvm qemu-img

 mkdir -p /kvm/pools/default
virsh pool-define-as --name default --type dir --target /kvm/pools/default

[root@dns-master ~]# virsh pool-autostart default
Pool default marked as autostarted

[root@dns-master ~]# virsh pool-start default
Pool default started

[root@dns-master ~]# virsh pool-list
 Name      State    Autostart
-------------------------------
 default   active   yes

[root@dns-master ~]# virsh pool-edit default

=======================================================================
### CRC CodeReady
sudo dnf install -y libvirt virt-manager virt-install virt-viewer libvirt-client qemu-kvm qemu-img

crc config set skip-check-daemon-systemd-unit true 
crc config set skip-check-daemon-systemd-sockets true
crc setup 
crc start  

$ crc config set cpus 8

$ crc config set memory 16384

 crc start -p ~/Downloads/pull-secret



======================================================================
### generate certificates and key local:

1- The Primary Certificate (your_domain_name.crt)
2- The Intermediate Certificate (DigiCertCA.crt)
3- The Root Certificate (TrustedRoot.crt)



openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem

openssl req -new -newkey rsa:2048 -nodes -keyout chatbot.faisal.com.eg.key -out chatbot.faisal.com.eg.csr

-rw-r--r-- 1 root root 1497 Nov 23 15:50 cert.pem
-rw-r--r-- 1 root root 1151 Nov 23 15:40 chatbot.faisal.com.eg.csr
-rw------- 1 root root 1704 Nov 23 15:39 chatbot.faisal.com.eg.key
-rw------- 1 root root 1704 Nov 23 15:49 key.pem

# display csr 
 openssl req -in ocp.spring.net.csr -noout -text -nameopt sep_multiline


## Extract key from pfx
openssl pkcs12 -in [yourfile.pfx] -nocerts -out [drlive.key]

# error Enter PEM passwrd , can be remove it
#seriously, If you'll know the passphrase you can remove it:

openssl rsa -in website.com.key_secure.key -out website.com.key
===================================================================
### Admin Domain create certifcate witk private key from windows server
1- file.pfx 
2- chatbot_fasisalbank_com_eg.crt  ---> Test on nginx  
3- chatbot_fasisalbank_com_eg.key  ---> Test on nginx 
4- DigiCertCA.crt 

## Check SSL 
https://www.ssllabs.com/ssltest/

## Create cerifcate and purchase on public SSL CA
https://www.tecmint.com/generate-csr-certificate-signing-request-in-linux/

#########################################################
#Extract the certificates and private key from the PFX file:
openssl pkcs12 -in yourfile.pfx -out certificates.pem -nodes

'This command will prompt you for the password of the PFX file (if it is password-protected). The -nodes option prevents the private key from being encrypted.'

#Open the certificates.pem file:
#Open the certificates.pem file in a text editor. This file contains all the certificates (the root, intermediate, and end-entity certificate) and possibly the private key.

## Verify the Extracted Certificate

openssl x509 -in intermediate.crt -text -noout


### Extract key from pfx
openssl pkcs12 -in [yourfile.pfx] -nocerts -out [drlive.key]

# error Enter PEM passwrd , can be remove it
#seriously, If you'll know the passphrase you can remove it:

openssl rsa -in website.com.key_secure.key -out website.com.key

## Exttract certificate from pfx
 openssl pkcs12 -in Bot_cert.pfx -clcerts -nokeys -out drlive.crt  -nodes

====================================================================================
====================================================================================
### Create two interface on linux in different interfaces
delete all IPv6 except (IPV6INIT=no)

 =========================================================================
 # cat /etc/machine-id
daab00e07fed481d8ccf145b7affc0c5

 rm /etc/machine-id

systemd-machine-id-setup
Initializing machine ID from random generator.

# cat /etc/machine-id
2175d9b2344a499abd87920c6f76f9a1
===================================================================
## 
Create a file '~/.vimrc' and paste the following (this helps with editing in vim, particularly yaml files):

cat <<EOT >> ~/.vimrc
syntax on
set nu et ai sts=0 ts=2 sw=2 list hls
EOT

export OC_EDITOR="vim"
export KUBE_EDITOR="vim"
===========================================================
# History
HISTSIZE=1000
HISTFILESIZE=2000
==================================
Fix Failed to download metadata for repo
CentOS Linux 8 had reached the End Of Life (EOL) on December 31st, 2021

Step 1: Go to the /etc/yum.repos.d/ directory.
cd /etc/yum.repos.d/

sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*

sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

 yum update -y

=====================================================
### What is Causing SSH Permission Denied (publickey,gssapi-keyex,gssapi-with-mic)?
sudo nano /etc/ssh/sshd_config
'
PasswordAuthentication yes
ChallengeResponseAuthentication no 
'

=====================================================
### Disable IPv6 on cenos 8
ip a | grep inet6
vi /etc/sysctl.d/70-ipv6.conf
'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
'
sysctl --load /etc/sysctl.d/70-ipv6.conf
ip a | grep inet6
=================================================
useradd -m jboss ; echo jboss: | chpasswd ; usermod -a -G wheel jboss

------------------------------------------------------------------
#!/bin/bash
# Script to add a user to Linux system
if [ $(id -u) -eq 0 ]; then
	read -p "Enter username : " username
	read -s -p "Enter password : " password
	egrep "^$username" /etc/passwd >/dev/null
	if [ $? -eq 0 ]; then
		echo "$username exists!"
		exit 1
	else
		pass=$(perl -e 'print crypt($ARGV[0], "password")' $password)
		useradd -m -p $pass $username
		[ $? -eq 0 ] && echo "User has been added to system!" || echo "Failed to add a user!"
	fi
	egrep "^$username" /etc/passwd >/dev/null
	if [ $? -eq 0 ]; then
		cp -pf /etc/sudoers /tmp/sudoers
		awk 'NR==101{print "asadmin         ALL=(ALL)       NOPASSWD: ALL"}1' /etc/sudoers > /tmp/sudoers
		\cp -pf /tmp/sudoers /etc/sudoers
		[ $? -eq 0 ] && echo "User has been added to sudoers!" || echo "Failed to add a user in sudoers!"
	else
		echo "$username not found in passwd file"
		exit 1
	fi 
else
	echo "Only root may add a user to the system"
	exit 2
fi

-----------------------------------------
### Check TCP & UDP 
# yum install nc
# yum install telnet

#Testing TCP port connectivity with telnet
$telnet [hostname/IP address] [port number]

#Using nc command to test TCP port connectivity
$nc -z -v [hostname/IP address] [port number]

#Testing UDP port connectivity wit nc command
$nc -z -v -u [hostname/IP address] [port number]

$nc -z -v -u -s 10.20.50.X -p 123 10.20.32.18 
for i in {134,135,182}; do  nc -zvu 10.20.48.$i 3303; done

===============================================
### Add static route  #ens256: 10.20.49.250
vi /etc/sysconfig/network-scripts/route-ens256
'
10.20.48.0/24 via 10.20.49.1 dev ens256
10.20.49.0/24 via 10.20.49.1 dev ens256
10.20.50.0/24 via 10.20.49.1 dev ens256
'
==================================================
### KVM Fixing MSR 0xe1 to 0x0
 
Edit the default grub file /etc/default/grub.
Within the grub file, add kvm.ignore_msrs=1 to the GRUB_CMDLINE_LINUX constant.
$vi /etc/default/grub
GRUB_CMDLINE_LINUX="console=ttyS0 console=ttyS0,115200n81 no_timer_check  crashkernel=auto rhgb quiet kvm.ignore_msrs=1"

$grub2-mkconfig -o "$(readlink -e /etc/grub2.conf)"
$cat /sys/module/kvm/parameters/ignore_msrs
'Y'
------------------------------------------
[amsadmin@ocp ~]$ su -c 'dnf -y install git wget tar qemu-kvm libvirt NetworkManager jq libselinux-python'

-------------------------------------------------

=================================================================================
## query list of config file for installed package
repoquery -q -l --plugins docker  

======================================================
##### password recovert on centos and ubuntu
rw init=/sysroot/bin/sh

chroot /sysroot          ## OR mount -o remount,rw /


password root

sync;sync;sync
reboot

========================================ubuntu##########333
replace “ro quiet splash $vt_handoff” word with “rw init=/bin/bash”.
Ctrl+X

=============================================================================
############################################# Sendmail from linux to gmail
Steps :

1. Install Mail Packages
   yum install postfix mailx cyrus-sasl cyrus-sasl-plain -y

2. Create GMail Account
   a) Generate App Password from account then security then search apps password 

2.1 edit the line in main.cf 
inet_interfaces=all
to
inet_interfaces=ipv4


3. Edit sasl_password file and add gmail account details
   vi /etc/postfix/sasl_passwd
   [smtp.gmail.com]:587 <emailid>@gmail.com:**********

4. Generate DB file
   postmap /etc/postfix/sasl_passwd
   
5. Edit main.cf
   relayhost = [smtp.gmail.com]:587
   myhostname = oracle-vm.com
   
   # Enable SASL authentication for postfix
   smtp_use_tls = yes                                                                                 
   smtp_sasl_auth_enable = yes   
   smtp_tls_security_level = encrypt
   smtp_tls_CAfile = /etc/ssl/certs/ca-bundle.crt
   
   # Disallow methods that allow anonymous authentication
   smtp_sasl_security_options = noanonymous    
   
   # Location of sasl_passwd   
   smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd

systemctl start postfix

 
6. Test EMAIL   
   echo "Test Email" | mail -s "Send Email from Linux" sendmailfromlinux@gmail.com


#################################################
## How to delete old kernel 

#==================================================================
# init 6
Authorization not available. Check if polkit service is running or see debug message for more information.

# reboot
Authorization not available. Check if polkit service is running or see debug message for more information.

# systemctl reboot
Authorization not available. Check if polkit service is running or see debug message for more information.


# Resolution
  mv /var/run /var/run.old
  mv /var/lock /var/lock.old

 ln -s /run /var/
  ln -s /run/lock /var/

 ln -s /run /var/
 ln -s /run/lock /var/

 ll /var/run
#lrwxrwxrwx. 1 root root 6 Feb  3 00:14 /var/run -> ../run
 ll /var/lock
#lrwxrwxrwx. 1 root root 11 Feb  3 00:14 /var/lock -> ../run/lock

sync

reboot

#======================================================================================
cd  /etc/pki/nssdb/    # Default path of database of certificates

##Import Intermediate Certificate 
certutil -d . -n "CA Sub <num>" -t "CT,C,C" -a -i ca_sub_<num>.crt


##Import Root Certificate
certutil -d . -n "Root CA" -t "C,C,C" -a -i root_ca.crt


dnf install pki-tool

##############The best important###############
cd  /etc/pki/nssdb/
PKICertImport -d . -n "CA Root" -t "CT,C,C" -a -i ca_root.crt -u L
PKICertImport -d . -n "CA SUB" -t "CT,C,C" -a -i ca_sub.crt -u L

## Test
openssl s_client -connect api.id.gov.sa:443 -showcerts | less

# Note that domain (api.id.gov.sa) in CN in certificate

## List
certutil -L -d sql:.
certutil -L -d sql:. -n "CA Root"
certutil -L -d sql:. -n "CA SUB"


## Delete the certificate by running the certutil with the -D option.
certutil -D -d . -n "CA Root"
certutil -D -d . -n "CA SUB"
############
## Update certificate on Java
keytool -import -trustcacerts -keystore /etc/java/java-11-openjdk/java-11-openjdk-11.0.14.1.1-6.el9.x86_64/lib/security/cacerts -storepass changeit -noprompt -alias nafath-user-new  -file /var/liferay/liferay-dxp/"mcit-sb.crt"

#############################
cd  /etc/pki/nssdb/
PKICertImport -d . -n "CA Root" -t "CT,C,C" -a -i ca_root.crt -u L
PKICertImport -d . -n "CA SUB" -t "CT,C,C" -a -i ca_sub.crt -u L

## Test
openssl s_client -connect api.id.gov.sa:443 -showcerts | less

# Note that domain (api.id.gov.sa) in CN in certificate


## List the certificates in the database
certutil -L -d .

Certificate Authority - Example Domain    CT,c,
subsystemCert cert-instance_name          u,u,u
Server-Cert cert-instance_name            u,u,u



## Delete the certificate by running the certutil with the -D option.
certutil -D -d . -n "ServerCert cert-instance_name"

############################################################################################
#1. Extract the Private Key

openssl pkcs12 -in yourfile.pfx -nocerts -out privatekey.pem -nodes

#2. Extract the Certificate
openssl pkcs12 -in yourfile.pfx -clcerts -nokeys -out certificate.pem

# 3. Extract Intermediate Certificates
openssl pkcs12 -in yourfile.pfx -cacerts -nokeys -out intermediates.pem

#4. Extract the Root Certificate (if included)
If the .pfx file includes the root certificate, it will be extracted along with the intermediate certificates in the previous step. You can manually separate the root certificate from the intermediates.pem file if needed

#5. Verify the Extracted Files
openssl rsa -in privatekey.pem -check
openssl x509 -in certificate.pem -text -noout
openssl x509 -in intermediates.pem -text -noout

#6. Combine Certificates (Optional)
# For some applications (e.g., Nginx, Apache), you may need to combine the certificate and intermediate certificates into a single file:
cat certificate.pem intermediates.pem > fullchain.pem

Notes
Ensure you keep the extracted private key (privatekey.pem) secure, as it is sensitive information.

If the .pfx file does not include intermediate or root certificates, you may need to download them separately from your Certificate Authority (CA).

By following these steps, you can successfully extract the certificate, private key, and intermediate certificates from a .pfx file.

###################################################################################################################
###  Openssl Script
Here's a comprehensive bash script to generate SSL certificates and keys using OpenSSL, with best practices for security and flexibility:

```bash
#!/bin/bash

# Certificate Generator Script
# Usage: ./generate_certs.sh [DOMAIN] [DAYS_VALID]

set -e  # Exit on error

# Default values
DOMAIN=${1:-"localhost"}
DAYS_VALID=${2:-365}
OUTPUT_DIR="./certs"
CONFIG_FILE="openssl.cnf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Generate OpenSSL config if it doesn't exist
if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
C = US
ST = California
L = San Francisco
O = My Organization
OU = IT Department
CN = $DOMAIN

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = *.$DOMAIN
IP.1 = 127.0.0.1
EOF
fi

echo -e "${GREEN}[+] Generating private key...${NC}"
openssl genpkey -algorithm RSA \
    -out "$OUTPUT_DIR/server.key" \
    -aes256 \
    -pass pass:temp_password \
    -pkeyopt rsa_keygen_bits:2048

# Remove password from key (optional)
echo -e "${GREEN}[+] Removing password from key...${NC}"
openssl rsa -in "$OUTPUT_DIR/server.key" \
    -passin pass:temp_password \
    -out "$OUTPUT_DIR/server.key"

echo -e "${GREEN}[+] Generating Certificate Signing Request...${NC}"
openssl req -new \
    -key "$OUTPUT_DIR/server.key" \
    -out "$OUTPUT_DIR/server.csr" \
    -config "$CONFIG_FILE"

echo -e "${GREEN}[+] Generating self-signed certificate...${NC}"
openssl x509 -req \
    -in "$OUTPUT_DIR/server.csr" \
    -signkey "$OUTPUT_DIR/server.key" \
    -out "$OUTPUT_DIR/server.crt" \
    -days "$DAYS_VALID" \
    -extensions v3_req \
    -extfile "$CONFIG_FILE"

echo -e "${GREEN}[+] Generating PEM file (combined crt+key)...${NC}"
cat "$OUTPUT_DIR/server.crt" "$OUTPUT_DIR/server.key" > "$OUTPUT_DIR/server.pem"

echo -e "${GREEN}[+] Generating Diffie-Hellman parameters...${NC}"
openssl dhparam -out "$OUTPUT_DIR/dhparam.pem" 2048

# Set proper permissions
chmod 600 "$OUTPUT_DIR"/*.key
chmod 644 "$OUTPUT_DIR"/*.crt

echo -e "\n${GREEN}[+] Certificate generation complete!${NC}"
echo -e "Files saved to: $OUTPUT_DIR/"
echo -e "\nGenerated files:"
ls -lh "$OUTPUT_DIR"/
```

## Key Features:

1. **Customizable Parameters**:
   - Domain name (default: localhost)
   - Validity period (default: 365 days)
   - Output directory (default: ./certs)

2. **Security Best Practices**:
   - 2048-bit RSA keys (minimum recommended)
   - SHA-256 hashing algorithm
   - Key encryption with password (then removed)
   - Proper file permissions (600 for keys)

3. **Generated Files**:
   - `server.key` - Private key
   - `server.crt` - Self-signed certificate
   - `server.csr` - Certificate Signing Request
   - `server.pem` - Combined certificate+key
   - `dhparam.pem` - Diffie-Hellman parameters

4. **SAN Support**:
   - Includes Subject Alternative Names (SAN)
   - Covers domain, wildcard, and localhost IP

## Usage Examples:

1. **Basic usage (default values)**:
   ```bash
   chmod +x generate_certs.sh
   ./generate_certs.sh
   ```

2. **Custom domain and validity**:
   ```bash
   ./generate_certs.sh example.com 730
   ```

3. **For Kubernetes/Ingress**:
   ```bash
   ./generate_certs.sh myapp.internal 365
   kubectl create secret tls myapp-tls \
       --cert=./certs/server.crt \
       --key=./certs/server.key
   ```

## Advanced Options:

To modify the script for different use cases:

1. **For wildcard certificates**:
   ```bash
   ./generate_certs.sh "*.example.com" 365
   ```

2. **For multiple domains**:
   Edit the `[alt_names]` section in the generated `openssl.cnf` file.

3. **For ECDSA keys** (instead of RSA):
   Replace the key generation with:
   ```bash
   openssl ecparam -genkey -name prime256v1 -out "$OUTPUT_DIR/server.key"
   ```

Would you like me to modify this script for any specific use case or add additional features?
=================================================================================================


#=============================================================================================
## How to delete subscription redhat 
subscription-manager list --consumed

#Enter a command as follows to remove the selected subscription:
subscription-manager remove --serial=serial_number

# To remove all subscriptions attached to the system, run the following command:
subscription-manager remove --all

#==================================================================================
the password you use to login to you computer no longer matches ubuntu
rm -f ~/.local/share/keyring/login.keyring 

#===================================================================
## WebProxy on nginx
location /socket.io/ {

    proxy_http_version 1.1;
    proxy_set_header Upgrade $https_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;

    proxy_pass  "https://localhost:8080/socket.io/";  # http://wsbackend;
}

nginx -t 
systemctl restart nginx 
#===================================================================================================
## WebSocket
wget -L https://github.com/vi/websocat/releases/download/v1.13.0/websocat.x86_64-unknown-linux-musl -O websocat
chmod +x websocat  

# Web server
./websocat -s 192.168.1.1:1234

# Connectio Test
./websocat ws://192.168.1.1:1234

## WSS
./websocat -E -t --pkcs12-der=q.pkcs12  wss-listen:127.0.0.1:1234 mirror:

./websocat --ws-c-uri=wss://localhost/ -t - ws-c:cmd:'socat - ssl:127.0.0.1:1234,verify=0'


# Online websocket
http://www.easyswoole.com/wstool.html

#==========================================================================================
{https://phoenixnap.com/kb/ssh-port-forwarding#:~:text=in%20a%20network.-,Local%20Port%20Forwarding%20with%20OpenSSH,IP%20address%20or%20a%20hostname.}

##########Local Port Forwarding with OpenSSH

#To use SSH tunneling in Linux, you must provide your client with the source and destination port numbers, as well as the location of the destination server. The location can either be an IP address or a hostname

ssh -L local_port:destination_server_ip:remote_port ssh_server_hostname

<<COMMENT
ssh                                             - Starts the SSH client program on the local machine and establishes a secure connection to the remote SSH server.
-L local_port:destination_server_ip:remote_port - The local port on the local client is being forwarded to the port of the destination remote server. Replace with your values.
ssh_server_hostname                             - This syntax element represents the hostname or IP address of the remote SSH server.A practical examp 
COMMENT

ssh -L 5901:188.17.0.5:4492 pnap@ssh.server.com

#In the example above, all traffic sent to port 5901 on your local host is being forwarded to port 4492 on the remote server located at 188.17.0.5.


ssh admin@10.10.0.13 -L 8444:10.10.0.13:3000



#-==============================================================================================
https://yum.oracle.com/getting-started.html
# Enable oracle repolistory
vi /etc/yum.repos.d/ol8-temp.repo
[ol8_baseos_latest]
name=Oracle Linux 8 BaseOS Latest ($basearch)
baseurl=https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/$basearch/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=1

dnf install oraclelinux-release-el8

 mv /etc/yum.repos.d/ol8-temp.repo /etc/yum.repos.d/ol8-temp.repo.disabled

 dnf update --setopt=ol8_appstream.module_hotfixes=true --allowerasing -y

 ### RHL9
 Red Hat Enterprise Linux 9
Import the Oracle Linux GPG key using these instructions.

Ceate a temporary yum repository configuration file /etc/yum.repos.d/ol9-temp.repo with the following as the minimum required content:

[ol9_baseos_latest]
name=Oracle Linux 9 BaseOS Latest  ($basearch)
baseurl=https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/$basearch/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=1
Install oraclelinux-release-el9:
# dnf install oraclelinux-release-el9
Remove ol9-temp.repo and any other remaining repo files that may conflict with Oracle Linux yum server:
# mv /etc/yum.repos.d/ol9-temp.repo /etc/yum.repos.d/ol9-temp.repo.disabled
You are now ready to install additional software. See: Installing Software from Oracle Linux Yum Server

[OPTIONAL] To update your system, proceed with the following command:

# dnf update --setopt=ol9_appstream.module_hotfixes=true --allowerasing -y

#==============================================================================
sudo apt-get update
sudo apt-get -y install xwayland

/etc/gdm3/custom.conf 
#Delete the # character from the beginning of the line WaylandEnable=false.

=============================================================
## Install epel on centos 9
dnf install 'dnf-command(config-manager)'
dnf config-manager --set-enabled crb
dnf install epel-release epel-next-release

#==========================================================
## In combination with rsync to back up, copy, and mirror files efficiently and securely to a local or remote host:
$ rsync -avul --rsh=ssh /opt/edbdata/ root@example.com:/root/backup/
root@example.com's password: ******
building file list ... done
./
file1.txt
file2.txt
file3.txt
file4.txt
dir1/file5.txt
dir2/file6.txt
 
sent 982813 bytes  received 2116 bytes  1374860.38 bytes/sec
total size is 982138  speedup is 1.00
'

/opt/freeware/bin/rsync -avzhprEogt signatures/ 172.17.73.6:/shared/browsert24/t24perf/signatures/


rsync -avzhprEogt  --delete

rsync -avzhprEogt --delete  --exclude='conf/.default'   --exclude='conf/t24perf.properties'  /t24/t24perf/TAFJ_SP31.1/   172.30.75.7:/t24/t24perf/TAFJ_SP31.1/  > /dev/null 2>&1

###  Note: syntax very import in exclude synatx

-avul
#######################################################################################
tar -czvf (archive name).tar.gz (pathtofile)

# efficincy GOOD
tar cfJ must-gather.local.5107228562763162803.tar.xz must-gather.local.5107228562763162803/

#############################################################
# number of cores
grep -c ^processor /proc/cpuinfo

#For systems with hyper-threading, you can use

grep ^cpu\\scores /proc/cpuinfo | uniq |  awk '{print $4}'

cat /proc/cpuinfo | awk '/^processor/{print $3}'
############################################################
#################################    Bash Experiances:

cat > /etc/hosts <<EOF
10.73.34.34 els-1 els-1.bmd.local
10.73.34.119  els-2 els-2.bmd.local
0.73.34.133  els-3 els-3.bmd.local
EOF

sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config
sudo systemctl stop firewalld
sudo systemctl disable firewalld

####################################################################################################################
**SSL Offloading** is the process of decrypting encrypted (HTTPS) traffic at a load balancer or reverse proxy before forwarding it to backend servers. This offloads the resource-intensive SSL/TLS decryption process from the backend servers, improving performance and simplifying certificate management.

---

### **How SSL Offloading Works**
1. **Client Request:** A client sends an HTTPS request to the server.
2. **Load Balancer/Reverse Proxy:** The load balancer or reverse proxy (e.g., Nginx, HAProxy, or AWS ELB) terminates the SSL/TLS connection.
3. **Decryption:** The load balancer decrypts the HTTPS traffic using the SSL/TLS certificate.
4. **Forwarding:** The decrypted traffic (HTTP) is forwarded to the backend servers.
5. **Response:** The backend servers process the request and send the response back to the load balancer, which re-encrypts it before sending it to the client.

---

### **Benefits of SSL Offloading**
1. **Improved Performance:**
   - Offloads the CPU-intensive SSL/TLS decryption process from backend servers.
   - Allows backend servers to focus on processing application logic.

2. **Simplified Certificate Management:**
   - SSL/TLS certificates are managed centrally on the load balancer or reverse proxy.
   - Reduces the need to install and update certificates on multiple backend servers.

3. **Enhanced Security:**
   - Centralized SSL/TLS termination makes it easier to enforce security policies and updates.
   - Protects backend servers from direct exposure to the internet.

4. **Scalability:**
   - Load balancers can handle a large number of SSL/TLS connections efficiently.
   - Backend servers can scale horizontally without managing SSL/TLS overhead.

---

### **Drawbacks of SSL Offloading**
1. **Single Point of Failure:**
   - If the load balancer fails, SSL/TLS termination is disrupted.
   - High availability (HA) setups are required to mitigate this risk.

2. **Potential Security Risks:**
   - Decrypted traffic between the load balancer and backend servers may be vulnerable if not properly secured (e.g., over an unencrypted HTTP connection).
   - Use of secure internal networks or re-encryption (SSL Bridging) is recommended.

---

### **SSL Offloading vs. SSL Bridging**
- **SSL Offloading:**
  - Traffic is decrypted at the load balancer and forwarded as plain HTTP to backend servers.
  - Suitable for trusted internal networks.

- **SSL Bridging:**
  - Traffic is decrypted at the load balancer and then re-encrypted before being sent to backend servers.
  - Provides end-to-end encryption but adds additional overhead.

---

### **Implementing SSL Offloading in Nginx**
To configure SSL offloading in Nginx:
1. Install an SSL/TLS certificate on the Nginx server.
2. Configure Nginx to terminate SSL/TLS and forward decrypted traffic to backend servers.

Example Nginx configuration:
```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;

    # SSL/TLS configuration
    ssl_certificate /etc/nginx/ssl/yourdomain.crt;
    ssl_certificate_key /etc/nginx/ssl/yourdomain.key;

    # Forward decrypted traffic to backend servers
    location / {
        proxy_pass http://backend_servers;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

upstream backend_servers {
    server 192.168.1.10;
    server 192.168.1.11;
}
```

---

### **Use Cases for SSL Offloading**
1. **Web Applications:**
   - Offload SSL/TLS processing for high-traffic websites or applications.
2. **Microservices Architecture:**
   - Simplify SSL/TLS management for multiple backend services.
3. **Cloud Environments:**
   - Use cloud load balancers (e.g., AWS ELB, Google Cloud Load Balancer) to handle SSL/TLS termination.

---

By implementing SSL offloading, you can improve the performance, scalability, and manageability of your infrastructure while maintaining security.

########################################################################################################################################################
## Performance tunning on Linux:
Configuring performance tuning on Red Hat Linux (RHEL) involves optimizing system parameters, kernel settings, hardware utilization, and application configurations. Below is a step-by-step guide to improve performance for specific workloads (e.g., web servers, databases, or compute-intensive tasks):

---

### **1. Analyze System Performance**
Before tuning, identify bottlenecks using monitoring tools:
  ```bash
  # CPU/Memory
  top
  htop
  vmstat 1 10

  # Disk I/O
  iostat -x 1 10
  iotop

  # Network
  sar -n DEV 1 10
  iftop

  # General
  dstat --top-cpu --top-mem --top-io
  ```

---

### **2. Use Tuned Profiles (Predefined Optimizations)**
Red Hat provides the `tuned` daemon with predefined profiles for different workloads.

#### Enable a tuned profile:
  ```bash
  # List available profiles
  tuned-adm list

  # Activate a profile (e.g., throughput-performance)
  tuned-adm profile throughput-performance

  # Verify active profile
  tuned-adm active
  ```

#### Common profiles:
  - **throughput-performance**: Optimized for high throughput.
  - **latency-performance**: Prioritizes low latency.
  - **virtual-guest**: For virtual machines.
  - **network-latency**: Optimized for low network latency.

---

### **3. Kernel Parameter Tuning**
Adjust kernel parameters via `/etc/sysctl.conf` or custom files in `/etc/sysctl.d/`.

#### Example optimizations:
  ```bash
  # Increase TCP buffer sizes
  net.core.rmem_max = 16777216
  net.core.wmem_max = 16777216
  net.ipv4.tcp_rmem = 4096 87380 16777216
  net.ipv4.tcp_wmem = 4096 65536 16777216

  # Increase file handles and inotify limits
  fs.file-max = 1000000
  fs.inotify.max_user_watches = 1000000

  # Reduce swap usage (vm.swappiness=0 for no swap, 10 for minimal)
  vm.swappiness = 10

  # Enable TCP fast open
  net.ipv4.tcp_fastopen = 3

  # Apply changes
  sysctl -p
  ```

---

### **4. Disk I/O Optimization**
#### a. **I/O Scheduler Tuning**
  Choose the appropriate I/O scheduler for your disk type (SSD vs. HDD):
  ```bash
  # Check current scheduler
  cat /sys/block/sdX/queue/scheduler

  # Set scheduler (e.g., deadline for HDD, none/noop for SSD)
  echo deadline > /sys/block/sdX/queue/scheduler

  # Make permanent (use udev rules or grubby)
  # Example: Add elevator=deadline to GRUB_CMDLINE_LINUX in /etc/default/grub
  grubby --update-kernel=ALL --args="elevator=deadline"
  ```

#### b. **Filesystem Mount Options**
  Modify `/etc/fstab` to optimize mount options:
  ```bash
  # For XFS/ext4 (add noatime, nodiratime, and barrier=0 if using battery-backed RAID)
  UUID=xxxx /data xfs defaults,noatime,nodiratime,barrier=0 0 0
  ```

---

### **5. CPU and NUMA Tuning**
#### a. **Disable CPU Frequency Scaling**
  Set CPUs to `performance` mode:
  ```bash
  # Install tools
  yum install -y kernel-tools

  # Set governor
  cpupower frequency-set -g performance

  # Verify
  cpupower frequency-info
  ```

#### b. **NUMA Balancing**
  For NUMA systems, disable automatic balancing if applications are NUMA-aware:
  ```bash
  echo 0 > /proc/sys/kernel/numa_balancing
  ```

---

### **6. Memory Management**
#### a. **Transparent Huge Pages (THP)**
  Disable THP if latency-sensitive (e.g., databases):
  ```bash
  # Check status
  cat /sys/kernel/mm/transparent_hugepage/enabled

  # Disable (add to /etc/rc.local)
  echo never > /sys/kernel/mm/transparent_hugepage/enabled
  echo never > /sys/kernel/mm/transparent_hugepage/defrag
  ```

#### b. **Adjust Overcommit Settings**
  Modify memory overcommit behavior in `/etc/sysctl.conf`:
  ```bash
  vm.overcommit_memory = 0  # Default (heuristic)
  # vm.overcommit_memory = 2  # Strict (no overcommit)
  ```

---

### **7. Network Tuning**
#### a. **Increase Network Buffers**
  ```bash
  # Add to /etc/sysctl.conf
  net.core.netdev_max_backlog = 30000
  net.core.somaxconn = 1024
  net.ipv4.tcp_max_syn_backlog = 1024
  ```

#### b. **Enable TCP BBR (Congestion Control)**
  For modern networks:
  ```bash
  echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
  sysctl -p
  ```

---

### **8. Application-Specific Tuning**
#### a. **Web Servers (e.g., Nginx/Apache)**
  - Increase worker processes/connections.
  - Enable caching and keepalive.

#### b. **Databases (e.g., PostgreSQL/MySQL)**
  - Adjust buffer pool sizes (`shared_buffers`, `innodb_buffer_pool_size`).
  - Optimize query caching and indexing.

---

### **9. Security Limits**
Modify `/etc/security/limits.conf` to increase user/process limits:
  ```bash
  * soft nofile 100000
  * hard nofile 100000
  * soft nproc 65535
  * hard nproc 65535
  ```

---

### **10. Verify and Monitor Changes**
After tuning, use tools like `sysbench`, `fio`, or `stress-ng` to benchmark performance. Continuously monitor with:
  ```bash
  sar -A       # System Activity Reporter
  perf top     # CPU profiling
  pidstat      # Process-level stats
  ```

---

### **Final Notes**
- **Test in Staging**: Always test changes in a non-production environment.
- **Document Changes**: Track modifications to revert if issues arise.
- **Use RHEL Tools**: Leverage `tuna`, `numactl`, and `systemtap` for advanced tuning.

By following these steps, you can significantly improve the performance of your Red Hat Linux system for specific workloads.


# Gemini
** CPU Frequency Scaling:
** Governors: Control CPU frequency scaling (e.g., performance, powersave, conservative, ondemand).
** Choose based on workload:
** performance: For maximum performance, but higher power consumption.
** powersave: For lower power consumption, but may impact performance.   
#Check and adjust:
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 
echo "performance" > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor



####################################################################################
## How to install GNOME desktop environment
# yum group list
Available environment groups:
   Minimal Install
   Infrastructure Server
   File and Print Server
   Basic Web Server
   Virtualization Host
   Server with GUI
.....

yum groupinstall "Server with GUI"
#OR core GNOME packages: 
yum groupinstall 'X Window System' 'GNOME'

systemctl set-default graphical.target

reboot

# Remove GUI
# From RedHat
$ dnf groupinstall -y “Minimal Install”
$ dnf groupremove -y “Server with GUI”
$ dnf groupinstall -y “Server”


systemctl enable --now cockpit.socket
sudo firewall-cmd --add-service=cockpit --permanent

############################################################
#########################################  F5 BIG-IP ########################

To resolve **TCP RST (reset)** issues on an F5 BIG-IP Load Balancer, you need to identify why connections are being abruptly terminated and adjust configurations accordingly. Below are common causes and step-by-step solutions:

---

### **Common Causes of TCP RST**
1. **Backend Server Issues**  
   - Servers closing connections unexpectedly (e.g., due to misconfiguration or crashes).
2. **F5 BIG-IP Configuration**  
   - Idle timeout settings, TCP profile mismatches, or health monitor failures.
3. **Network Issues**  
   - Firewalls, routers, or switches sending RST packets.
4. **Client-Side Problems**  
   - Clients terminating connections prematurely.

---

### **Step-by-Step Fixes**

#### 1. **Verify Backend Server Health**
   - Ensure backend servers are responsive and not closing connections prematurely.
   - Check health monitors (`Local Traffic > Monitors`) to confirm servers are marked "up."
   - Use `tcpdump` on backend servers to see if they are sending RST packets:
     ```bash
     tcpdump -i any 'tcp[tcpflags] & (tcp-rst) != 0'
     ```

#### 2. **Adjust F5 TCP Profile Settings**
   - **Increase Idle Timeout**:  
     If connections are timing out, increase the `Idle Timeout` in the TCP profile.
     - Navigate to **Local Traffic > Profiles > TCP**.  
     - Edit the profile (or create a custom one) and adjust:
       - `Idle Timeout`: Set to match backend server expectations (e.g., `300` seconds).
       - `Reset on Timeout`: Disable this to send a TCP FIN instead of RST on timeout.  
         ![F5 TCP Profile](https://i.imgur.com/1R0sHlL.png)

   - **Match TCP Handshake Settings**:  
     Ensure the F5’s `TCP Handshake Timeout` aligns with client/server expectations.

#### 3. **Check Persistence Settings**
   - If persistence (e.g., source IP, cookie) is misconfigured, clients might be directed to invalid connections.
   - Navigate to **Local Traffic > Profiles > Persistence** and verify settings.

#### 4. **Disable TCP Reset on HTTP Errors**
   - If the F5 is sending RST packets for HTTP errors (e.g., 503), disable this behavior:
     ```bash
     tmsh modify ltm profile http <profile-name> reset-on-error disabled
     ```

#### 5. **Inspect SSL/TLS Offloading**
   - If SSL is terminated at the F5, ensure backend servers are not expecting encrypted traffic.
   - Verify SSL profiles (**Local Traffic > Profiles > SSL**) for mismatched ciphers or protocols.

#### 6. **Analyze Network Traffic**
   - Use `tcpdump` on the F5 to capture RST packets and identify their source:
     ```bash
     tmsh run /sys connection cslog -c <client-ip> <client-port> <server-ip> <server-port>
     tcpdump -ni 0.0:nnn 'tcp[tcpflags] & (tcp-rst) != 0'
     ```
   - Check for asymmetric routing or firewall interference between F5 and servers.

#### 7. **Review F5 Logs**
   - Check system logs for connection resets:
     ```bash
     tail -f /var/log/ltm
     tail -f /var/log/secure
     ```
   - Use `qkview` to collect diagnostics:
     ```bash
     qkview -f
     ```

#### 8. **Update F5 Firmware**
   - If the issue is caused by a software bug, upgrade to the latest stable version of BIG-IP:
     ```bash
     tmsh install sys software image <image-name>
     ```

---

### **Example: Disable Reset on Timeout**
1. Create a custom TCP profile:
   ```bash
   tmsh create ltm profile tcp my_custom_tcp_profile idle-timeout 300 reset-on-timeout disabled
   ```
2. Assign the profile to the virtual server:
   ```bash
   tmsh modify ltm virtual <vs-name> profiles add { my_custom_tcp_profile }
   ```

---

### **Key Commands for Troubleshooting**
| Command | Description |
|---------|-------------|
| `tmsh show sys connection cs-server-addr <ip>` | View active connections to a server. |
| `tmsh show ltm virtual <vs-name> stats` | Check virtual server statistics. |
| `netstat -an | grep <port>` | Check port status on backend servers. |

---

By addressing these areas, you can resolve TCP RST issues and ensure stable traffic handling on your F5 BIG-IP Load Balancer. Always test changes in a non-production environment first!
##################################
## F5 Troubleshooting
On F5: Local Traffic: Network Map:
             HTTPS_VS1           # Virtual Server
               HTTPS_POOL        # Pool Name
                 10.80.50.80:443 # Member-1
                 10.80.50.81:443 # Member-2

On F5: Local TrafficL Pools : Pool List:
    HTTPS_POOL:
      Properties:
      Health Monitors: /common
                        https 

on F5: statistics: Module Statistics: Local Traffic:
                                        Statistics Type: Pools 
On F5: Local Traffic: Virtual Servers: Virtual Server List: HTTPS_VS1
                               Source Address Translation: Auto Map 


From F5 CLI:
 openssh s_client -connect 172.16.1.50:443 #(server1)#
# Secure Renegotiation IS NOT Supported

F5: Locale Traffic: Profiles: SSL: Server:
     click on certificates 
     Secure Renegotiation : Request 

################ Solved RST 
source: https://youtu.be/BoXh5CAED0w?list=PLQUiLs8Ui40syrRkBc9YkqQXpgv3nCE0O

####################################################





##########################################################################################################
## flush DNS
sudo systemd-resolve --flush-caches

#################################################
###  Proxmox  fixed datavg lock
The error TASK ERROR: activating LV 'datavg/datavg' failed: Activation of logical volume datavg/datavg is prohibited while logical volume datavg/datavg_tmeta is active in Proxmox

root@pve:~# lvs -a -o +lv_active datavg | less

root@pve:~# lvchange -an datavg/datavg_tmeta
root@pve:~# lvchange -an datavg/datavg
root@pve:~# lvchange -ay datavg/datavg
  Activation of logical volume datavg/datavg is prohibited while logical volume datavg/datavg_tdata is active.
root@pve:~# lvchange -an datavg/datavg_tdata
root@pve:~# lvchange -ay datavg/datavg
########
The error **`TASK ERROR: activating LV 'datavg/datavg' failed: Activation of logical volume datavg/datavg is prohibited while logical volume datavg/datavg_tmeta is active`** in Proxmox VE (PVE) occurs when there’s a conflict with LVM thin provisioning. Here’s how to diagnose and fix it:

---

### **Cause of the Error**
1. **LVM Thin Pool Conflict**:  
   The logical volume (LV) `datavg/datavg` is a thin pool, and its metadata volume (`datavg/datavg_tmeta`) is still marked as "active."  
2. **Improper Shutdown/Crash**:  
   The thin pool wasn’t properly deactivated (e.g., due to a sudden host reboot or storage failure).  
3. **Orphaned LVM Metadata**:  
   The system thinks the thin pool is still in use.

---

### **Solution**
#### **Step 1: Check Active LVs**
List all active logical volumes in the volume group (`datavg`):
```bash
sudo lvs -a -o +lv_active datavg
```
Look for `datavg/datavg_tmeta` or `datavg/datavg` with `active` status.

#### **Step 2: Deactivate the Thin Pool**
Force-deactivate the thin pool and its metadata:
```bash
sudo lvchange -an datavg/datavg_tmeta
sudo lvchange -an datavg/datavg
```

#### **Step 3: Reactivate the Thin Pool**
```bash
sudo lvchange -ay datavg/datavg
```

#### **Step 4: Verify**
Check if the LV is now active:
```bash
sudo lvs -a -o +lv_active datavg
```

---

### **If the Error Persists**
#### **Option 1: Reboot the Node**
A reboot can clear stuck LVM states:
```bash
sudo reboot
```

#### **Option 2: Manually Reset LVM**
1. Unmount any filesystems using the LV:
   ```bash
   sudo umount /dev/datavg/datavg
   ```
2. Use `dmsetup` to remove the device mapper entry:
   ```bash
   sudo dmsetup remove /dev/datavg/datavg
   sudo dmsetup remove /dev/datavg/datavg_tmeta
   ```
3. Retry activation:
   ```bash
   sudo vgchange -ay datavg
   ```

#### **Option 3: Repair Thin Pool (Advanced)**
If corruption is suspected:
```bash
sudo lvconvert --repair datavg/datavg
```
**Warning**: This may cause data loss! Ensure you have backups.

---

### **Prevention Tips**
1. **Avoid Hard Reboots**: Always shut down PVE properly.  
2. **Monitor Thin Pools**: Use `lvs` to check for inconsistencies.  
3. **Backup LVM Metadata**:
   ```bash
   sudo vgcfgbackup datavg
   ```

---

### **Proxmox-Specific Fixes**
1. **Restart PVE Services**:
   ```bash
   sudo systemctl restart pve-cluster pvedaemon pveproxy
   ```
2. **Check Storage Configuration**:
   - Verify `/etc/pve/storage.cfg` for errors.  
   - Ensure the storage is not locked (e.g., `rm /var/lock/pve-manager/lock-*`).

---

### **Final Notes**
- This error is common with **LVM thin provisioning** in Proxmox.  
- If the issue persists, check Proxmox logs:
  ```bash
  journalctl -u pve-storage -b
  ```
- For mission-critical systems, consider using **ZFS** instead of LVM thin pools.

Need further help? Share the output of:
```bash
sudo lvs -a -o +lv_active datavg && sudo pvesm status
```
##########################

## How to install nginx offline
- Create new VM the same in environment as the target server.
- sudo dnf install --downloadonly --downloaddir=. nginx
- Copy the downloaded packages to the target server.
- On the target server, run:  
```bash
sudo rpm -Uvh nginx*.rpm
```
################################################################
## Search into each files
grep -Rin --binary-files-without-match --excude-dir={/tomcat/logs} "prod.mcit" . /tmp/prod.txt

grep -Rin "JAVA_HOME|JRE_HOME" /etc /usr /
