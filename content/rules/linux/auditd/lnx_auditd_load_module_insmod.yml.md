---
title: "Loading of Kernel Module via Insmod"
aliases:
  - "/rule/106d7cbd-80ff-4985-b682-a7043e5acb72"


tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1547.006



status: experimental





date: Tue, 2 Nov 2021 17:04:39 +0100


---

Detects loading of kernel modules with insmod command. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. Adversaries may use LKMs to obtain persistence within the system or elevate the privileges.

<!--more-->


## Known false-positives

* Unknown



## References

* https://attack.mitre.org/techniques/T1547/006/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.006/T1547.006.md
* https://linux.die.net/man/8/insmod
* https://man7.org/linux/man-pages/man8/kmod.8.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_load_module_insmod.yml))
```yaml
title: Loading of Kernel Module via Insmod
id: 106d7cbd-80ff-4985-b682-a7043e5acb72
status: experimental
description: Detects loading of kernel modules with insmod command. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. Adversaries may use LKMs to obtain persistence within the system or elevate the privileges.
author: 'Pawel Mazur'
date: 2021/11/02
references:
    - https://attack.mitre.org/techniques/T1547/006/
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.006/T1547.006.md
    - https://linux.die.net/man/8/insmod
    - https://man7.org/linux/man-pages/man8/kmod.8.html
logsource:
    product: linux
    service: auditd
detection:
    insmod:
        type: 'SYSCALL'
        comm: insmod
        exe: /usr/bin/kmod
    condition: insmod
falsepositives:
    - Unknown
level: high
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1547.006

```
