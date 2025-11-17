#!/usr/bin/env bash

SCORE=0
echo ""
# Disable unused filesystems - cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf, vfat,
if [[ "$(modprobe -n -v cramfs 2>/dev/null)" = "install /bin/true" ]] && [[ -z "$(lsmod | grep cramfs)" ]]; then
	echo "++ cramfs is disabled ++"
	((SCORE+=1))
else
	echo "-- cramfs is loadable or enabled --"
fi

if [[ "$(modprobe -n -v freevxfs 2>/dev/null)" = "install /bin/true" ]] && [[ -z "$(lsmod | grep freevxfs)" ]]; then
	echo "++ freevxfs is disabled ++"
	((SCORE+=1))
else
	echo "-- freevxfs is loadable or enabled --"
fi

# Separat partition for /tmp
if [[ "$(mount | grep /tmp)" = "tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)" ]]; then
	echo "++ /tmp is on a separate partition ++"
	((SCORE+=1))
else
	echo "-- /tmp is not on a separate partition or wrong option set --"
fi

# gpgcheck is activated
if [[ "$(grep ^gpgcheck /etc/yum.conf)" = "gpgcheck=1" ]] && [[ "$(grep ^gpgcheck /etc/yum.repos.d/* | wc -l)" -gt "$(ls /etc/yum.repos.d/ | wc -l)" ]]; then
	echo "++ Package signature verification for yum is enabled ++"
	((SCORE+=1))
else
	"-- Package signature verification for yum is disabled --"
fi

# aide
if [[ -z "$(rpm -q aide | grep "not installed")" ]]; then
	echo "-- Aide is not installed --"
else
	echo "++ Aide is installed ++"
	((SCORE+=1))
fi

# 1.4.3
if [[ "$(grep /sbin/sulogin /usr/lib/systemd/system/rescue.service)" = "ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" ]] && [[ "$(grep /sbin/sulogin /usr/lib/systemd/system/emergency.service)" = "ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" ]]; then
	echo "++ Authentication for single user mode is enabled ++"
	((SCORE+=1))
else
	echo "-- Authentication for single user mode is disabled --"
fi

# 1.5.2
if [[ -n "$(dmesg | grep "NX (Execute Disable) protection: active")" ]]; then
	echo "++ Kernel has activated NX/XD protection ++"
	((SCORE+=1))
else
	echo "-- Kernel has no active NX/XD protection --"
fi

# 1.5.4
if [[ "$(rpm -q prelink)" = "package prelink is not installed" ]]; then
	echo "++ Package prelink is not installed ++"
	((SCORE+=1))
else
	echo "-- Package prelink is installed --"
fi

# 1.6.1.2
if [[ -n "$(grep SELINUX=enforcing /etc/selinux/config)" ]] && [[ -n "$(sestatus) | grep "enabled")" ]]; then
	echo "++ SELinux is enabled and in enforcing mode ++"
	((SCORE+=1))
else
	echo "-- SELinux is disabled or not in enforcing mode --"
fi

# 1.6.1.3
if [[ -n "$(grep SELINUXTYPE=targeted /etc/selinux/config)" ]] && [[ -n "$(sestatus) | grep "targeted")" ]]; then
	echo "++ SELinux is enabled in targeted policy mode ++"
	((SCORE+=1))
else
	echo "-- SELinux is disabled or not in targeted policy mode --"
fi

# 1.7.1.3
if [[ -n "$(grep -E '(\\v|\\r|\\m|\\s)' /etc/issue)" ]]; then
	echo "== Details of the OS are displayed prior to login for local terminals =="
else
	echo "== Details of the OS are not displayed prior to login for local terminals =="
fi

# 1.7.1.3
if [[ -n "$(grep -E '(\\v|\\r|\\m|\\s)' /etc/issue.net)" ]]; then
	echo "== Details of the OS are displayed prior to login for remote connections =="
else
	echo "== Details of the OS are not displayed prior to login for remote connections =="
fi

# 1.8
if [[ -n "$(yum check-update --security | grep "No packages needed for security")" ]]; then
	echo "++ No packages needed for security ++"
	((SCORE+=1))
else
	echo "-- Update packages needed for security --"	
fi

# 2.1.7
if [[ -n "$(systemctl list-unit-files --full -all | grep -Fq "xinetd.service")" ]]; then
	if [[ "$(systemctl is-enabled xinetd)" = "enabled" ]]; then
		echo "-- xinetd is enabled --"
	fi
else
	echo "++ xinetd is disabled ++"
	((SCORE+=1))
fi

# 2.2.1.1
if [[ -z "$(rpm -q ntp | grep "not installed")" ]] && [[ -z "$(rpm -q chrony | grep "not installed")" ]]; then
	echo "== ntp and chrony are not installed =="
else
	echo "== ntp and chrony are installed =="
fi

# 2.2.1.3
if  [[ -z "$(rpm -q chrony | grep "not installed")" ]] && [[ "$(grep ^OPTIONS /etc/sysconfig/chronyd)" =~ .*-u.*chrony.* ]] && [[ "$(grep "^(server|pool)" /etc/chrony.conf)" =~ .*remote-server.* ]]; then
	echo "++ chrony is configured ++"
	((SCORE+=1))
else
	echo "-- chrony is not configured --"	
fi

# 2.2.2
if [[ -n "$(rpm -qa xorg-x11*)" ]]; then
	echo "-- X Window System is installed --"
else
	echo "++ X Window System is not installed ++"
	((SCORE+=1))
fi

# 2.2.3
if [[ "$(systemctl is-enabled avahi-daemon)" = "disabled" ]]; then
	echo "++ Automatic discovery of network services is disabled ++"
	((SCORE+=1))
else
	echo "-- Automatic discovery of network services is enabled --"
fi

# 2.3.1
if  [[ -n "$(rpm -q ypbind | grep "not installed")" ]]; then
	echo "++ ypbind is not installed ++"
	((SCORE+=1))
else
	echo "-- ypbind is installed --"
fi

# 2.3.2
if  [[ -n "$(rpm -q rsh | grep "not installed")" ]]; then
	echo "++ rsh is not installed ++"
	((SCORE+=1))
else
	echo "-- rsh is installed --"
fi

# 3.1.1
if [[ "$(sysctl net.ipv4.ip_forward)" = "net.ipv4.ip_forward = 0" ]] && [[ "$(grep "net\.ipv4\.ip_forward" /etc/sysctl.conf /etc/sysctl.d/*)" = "net.ipv4.ip_forward = 0" ]]; then
	echo "++ IP forwarding is disabled ++"
	((SCORE+=1))
else
	echo "-- IP forwarding is enabled --"
fi

# 3.2.5
if [[ "$(sysctl net.ipv4.icmp_echo_ignore_broadcasts)" = "net.ipv4.icmp_echo_ignore_broadcasts = 1" ]] && [[ "$(grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*)" = "net.ipv4.icmp_echo_ignore_broadcasts = 1" ]]; then
	echo "++ The system is set to ignore all ICMP echo ++"
	((SCORE+=1))
else
	echo "-- The system is not set to ignore all ICMP echo --"
fi

# 3.2.6
if [[ "$(sysctl net.ipv4.icmp_ignore_bogus_error_responses)" = "net.ipv4.icmp_ignore_bogus_error_responses = 1" ]] && [[ "$(grep "net\.ipv4\.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*)" = "net.ipv4.icmp_ignore_bogus_error_responses = 1" ]]; then
	echo "++ The system is set to prevent logging bogus error responses ++"
	((SCORE+=1))
else
	echo "-- The system is not set to prevent logging bogus error responses --"
fi

# 3.3.1
if [[ "$(sysctl net.ipv6.conf.all.accept_ra)" = "net.ipv6.conf.all.accept_ra = 0" ]] && [[ "$(systctl net.ipv6.conf.default.accept_ra)" = "net.ipv6.conf.default.accept_ra = 0" ]] && [[ "$(grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*)" = "net.ipv6.conf.all.accept_ra = 0" ]] && [[ "$(grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*)" = "net.ipv6.conf.default.accept_ra = 0" ]]; then
	echo "== The system is set to reject IPv6 router advertisements =="
else
	echo "== The system is set to accept IPv6 router advertisements =="
fi

# 3.3.2
if [[ "$(sysctl net.ipv6.conf.all.accept_redirects)" = "net.ipv6.conf.all.accept_redirects = 0" ]] && [[ "$(systctl net.ipv6.conf.default.accept_redirects)" = "net.ipv6.conf.default.accept_redirects = 0" ]] && [[ "$(grep "net\.ipv6\.conf\.all\.accept_redirect" /etc/sysctl.conf /etc/sysctl.d/*)" = "net.ipv6.conf.all.accept_redirects = 0" ]] && [[ "$(grep "net\.ipv6\.conf\.default\.accept_redirect" /etc/sysctl.conf /etc/sysctl.d/*)" = "net.ipv6.conf.default.accept_redirects = 0" ]]; then
	echo "== The system is set to reject ICMP redirects =="
else
	echo "== The system is set to accept ICMP redirects =="
fi

# 3.4.1
if  [[ -z "$(rpm -q tcp_wrappers | grep "not installed")" ]] && [[ -z "$(rpm -q tcp_wrappers-libs | grep "not installed")" ]]; then
	echo "++ tcp_wrappers, tcp_wrappers-libs installed ++"
	((SCORE+=1))
else
	echo "-- tcp_wrappers, tcp_wrappers-libs not installed --"	
fi

# 3.4.3
if [[ -n "$(cat /etc/hosts.deny | grep "ALL: ALL")" ]]; then
	echo "++ /etc/hosts.deny is configured rightly ++"
	((SCORE+=1))
else
	echo "-- /etc/hosts.deny is not configured rightly --"
fi

# 3.5.2
if [[ "$(modprobe -n -v sctp)" = "install /bin/true" ]] && [[ -z "$(lsmod | grep sctp)" ]]; then
	echo "== sctp is disabled completely =="
else
	echo "== sctp is not disabled completely =="
fi

# 3.5.1
if [[ "$(modprobe -n -v dccp)" = "install /bin/true" ]] && [[ -z "$(lsmod | grep dccp)" ]]; then
	echo "== dccp is disabled completely =="
else
	echo "== dccp is not disabled completely =="
fi

# 3.6.1
if  [[ -z "$(rpm -q iptables | grep "not installed")" ]]; then
	echo "++ iptables is installed ++"
	((SCORE+=1))
else
	echo "-- iptables is not installed --"
fi

# 3.6.2 REJECT
if [[ -n "$(iptables -L | grep "Chain INPUT (policy DROP)")" ]] && [[ -n "$(iptables -L | grep "Chain FORWARD (policy DROP)")" ]] && [[ -n "$(iptables -L | grep "Chain OUTPUT (policy DROP)")" ]]; then
	echo "++ INPUT, OUTPUT, and FORWARD chains is DROP ++"
	((SCORE+=1))
else
	echo "-- INPUT, OUTPUT, and FORWARD chains is not DROP --"
fi

# 4.1.2
if [[ "$(systemctl is-enabled auditd)" = "enabled" ]]; then
	echo "++ auditd is enabled ++"
	((SCORE+=1))
else
	echo "-- auditd is disabled --"	
fi

# 4.1.7 sudo
if [[ "$(grep MAC-policy /etc/audit/audit.rules)" = "-w /etc/selinux/ -p wa -k MAC-policy\\n-w /usr/share/selinux/ -p wa -k MAC-policy" ]]; then
	echo "++ SELinux MAC-policy configured for security ++"
	((SCORE+=1))
else
	echo "-- SELinux MAC-policy is not configured for security --"	
fi	

# 4.2.1.1
if [[ "$(systemctl is-enabled rsyslog)" = "enabled" ]]; then
	echo "++ rsyslog is enabled ++"
	((SCORE+=1))
else
	echo "-- rsyslog is disabled --"	
fi

# 4.2.2.1
if [[ -n "$(systemctl list-unit-files --full -all | grep -Fq "syslog-ng.service")" ]]; then
	if [[ "$(systemctl is-enabled syslog-ng)" = "enabled" ]]; then
		echo "++ syslog-ng is enabled ++"
		((SCORE+=1))
	fi
else
	echo "-- syslog-ng is disabled --"
fi

# 5.1.1
if [[ "$(systemctl is-enabled crond)" = "enabled" ]]; then
	echo "++ crond is enabled ++"
	((SCORE+=1))
else
	echo "-- crond is disabled --"
fi

# 5.2.2 sudo
if [[ "$(grep "^Protocol" /etc/ssh/sshd_config)" = "Protocol 2" ]]; then
	echo "++ SSH is configured to use v2 protocol ++"
	((SCORE+=1))
else
	echo "-- SSH is configured to use v1 protocol --"
fi	

# 5.2.3 sudo
if [[ "$(grep "^LogLevel" /etc/ssh/sshd_config)" = "LogLevel INFO" ]]; then
	echo "++ SSH is configured for logging at INFO level ++"
	((SCORE+=1))
else
	echo "-- SSH is not configured for logging at INFO level --"
fi

# 5.3.3 greater or equal to 5
if [[ "$(grep -E '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth)" =~ .*remember=5.* ]] && [[ "$(grep -E '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth)" =~ .*remember=5.* ]]; then
	echo "++ Password reuse is limited ++"
	((SCORE+=1))
else
	echo "-- Password reuse is not limited --"
fi

# 5.3.4
if [[ -n "$(grep -E '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth | grep "sha512")" ]] && [[ -n "$(grep -E '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth | grep "sha512")" ]]; then
	echo "++ SHA512 is used for password encryption ++"
	((SCORE+=1))
else
	echo "-- SHA512 is not used for password encryption --"
fi

# 5.4.3
if [[ "$(grep "^root:" /etc/passwd | cut -f4 -d:)" -eq 0 ]]; then
	echo "++ Default group for the root account is GID 0 ++"
	((SCORE+=1))
else
	echo "-- Default group for the root account is not GID 0 --"
fi

# 5.4.4
if [[ "$(grep "^TMOUT" /etc/bashrc | cut -d= -f2)" -lt 600 ]] && [[ "$(grep "^TMOUT" /etc/profile | cut -d= -f2)" -lt 600 ]]; then
	echo "++ Default user shell timeout is 600 seconds or less ++"
	((SCORE+=1))
else
	echo "-- Default user shell timeout is more than 600 seconds --"
fi

# 6.2.1 sudo
if [[ -n "$(stat /etc/passwd | grep "644")" ]] && [[ -n "$(stat /etc/passwd | grep "Uid: (    0/   root)")" ]] && [[ -n "$(stat /etc/passwd | grep "Uid: (    0/   root)")" ]]; then
	echo "++ /etc/passwd file permissions are right ++"
	((SCORE+=1))
else
	echo "-- /etc/passwd file permissions are not right --"
fi

# 6.2.2 sudo
if [[ -n "$(stat /etc/shadow | grep "0000")" ]] && [[ -n "$(stat /etc/shadow | grep "Uid: (    0/   root)")" ]] && [[ -n "$(stat /etc/shadow | grep "Uid: (    0/   root)")" ]]; then
	echo "++ /etc/shadow file permissions are right ++"
	((SCORE+=1))
else
	echo "-- /etc/shadow file permissions are not right --"
fi

# 6.2.4
if [[ -z "$(grep '^\+:' /etc/group)" ]]; then
	echo "++ No legacy '+' entries exist in /etc/group ++"
	((SCORE+=1))
else
	echo "-- Legacy '+' entries exist in /etc/group --"
fi
echo ""
echo "Benchmark Score of $SCORE of 36"
