---
title: "Privilege Escalation Preparation"
aliases:
  - "/rule/444ade84-c362-4260-b1f3-e45e20e1a905"
ruleid: 444ade84-c362-4260-b1f3-e45e20e1a905

tags:
  - attack.execution
  - attack.t1059.004



status: test





date: Sun, 7 Apr 2019 15:36:19 +0200


---

Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation.

<!--more-->


## Known false-positives

* Troubleshooting on Linux Machines



## References

* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
* https://patrick-bareiss.com/detect-privilege-escalation-preparation-in-linux-with-sigma/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/builtin/lnx_shell_priv_esc_prep.yml))
```yaml
title: Privilege Escalation Preparation
id: 444ade84-c362-4260-b1f3-e45e20e1a905
status: test
description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation.
author: Patrick Bareiss
references:
  - https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
  - https://patrick-bareiss.com/detect-privilege-escalation-preparation-in-linux-with-sigma/
date: 2019/04/05
modified: 2021/11/27
logsource:
  product: linux
detection:
  keywords:
        # distribution type and kernel version
    - 'cat /etc/issue'
    - 'cat /etc/*-release'
    - 'cat /proc/version'
    - 'uname -a'
    - 'uname -mrs'
    - 'rpm -q kernel'
    - 'dmesg | grep Linux'
    - 'ls /boot | grep vmlinuz-'
        # environment variables
    - 'cat /etc/profile'
    - 'cat /etc/bashrc'
    - 'cat ~/.bash_profile'
    - 'cat ~/.bashrc'
    - 'cat ~/.bash_logout'
        # applications and services as root
    - 'ps -aux | grep root'
    - 'ps -ef | grep root'
        # scheduled tasks
    - 'crontab -l'
    - 'cat /etc/cron*'
    - 'cat /etc/cron.allow'
    - 'cat /etc/cron.deny'
    - 'cat /etc/crontab'
        # search for plain text user/passwords
    - 'grep -i user *'
    - 'grep -i pass *'
        # networking
    - 'ifconfig'
    - 'cat /etc/network/interfaces'
    - 'cat /etc/sysconfig/network'
    - 'cat /etc/resolv.conf'
    - 'cat /etc/networks'
    - 'iptables -L'
    - 'lsof -i'
    - 'netstat -antup'
    - 'netstat -antpx'
    - 'netstat -tulpn'
    - 'arp -e'
    - 'route'
        # sensitive files
    - 'cat /etc/passwd'
    - 'cat /etc/group'
    - 'cat /etc/shadow'
        # sticky bits
    - 'find / -perm -u=s'
    - 'find / -perm -g=s'
    - 'find / -perm -4000'
    - 'find / -perm -2000'
  timeframe: 30m
  condition: keywords | count() by host > 6
falsepositives:
  - Troubleshooting on Linux Machines
level: medium
tags:
  - attack.execution
  - attack.t1059.004

```