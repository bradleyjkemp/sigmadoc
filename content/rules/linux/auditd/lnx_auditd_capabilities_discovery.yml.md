---
title: "Linux Capabilities Discovery"
aliases:
  - "/rule/fe10751f-1995-40a5-aaa2-c97ccb4123fe"
ruleid: fe10751f-1995-40a5-aaa2-c97ccb4123fe

tags:
  - attack.collection
  - attack.privilege_escalation
  - attack.t1123
  - attack.t1548



status: experimental





date: Sun, 28 Nov 2021 16:48:37 +0100


---

Detects attempts to discover the files with setuid/setgid capabilitiy on them. That would allow adversary to escalate their privileges.

<!--more-->


## Known false-positives

* None



## References

* https://man7.org/linux/man-pages/man8/getcap.8.html
* https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/
* https://mn3m.info/posts/suid-vs-capabilities/
* https://int0x33.medium.com/day-44-linux-capabilities-privilege-escalation-via-openssl-with-selinux-enabled-and-enforced-74d2bec02099


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_capabilities_discovery.yml))
```yaml
title: Linux Capabilities Discovery
id: fe10751f-1995-40a5-aaa2-c97ccb4123fe
description: Detects attempts to discover the files with setuid/setgid capabilitiy on them. That would allow adversary to escalate their privileges.
author: 'Pawel Mazur'
status: experimental
date: 2021/11/28
references:
   - https://man7.org/linux/man-pages/man8/getcap.8.html
   - https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/
   - https://mn3m.info/posts/suid-vs-capabilities/
   - https://int0x33.medium.com/day-44-linux-capabilities-privilege-escalation-via-openssl-with-selinux-enabled-and-enforced-74d2bec02099
logsource:
   product: linux
   service: auditd
detection:
   getcap:
       type: EXECVE
       a0: getcap
       a1: '-r'
       a2: '/'
   condition: getcap
tags:
   - attack.collection
   - attack.privilege_escalation
   - attack.t1123
   - attack.t1548
falsepositives:
   - None
level: low
```
