---
title: "System Shutdown/Reboot"
aliases:
  - "/rule/4cb57c2f-1f29-41f8-893d-8bed8e1c1d2f"


tags:
  - attack.impact
  - attack.t1529



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.

<!--more-->


## Known false-positives

* Legitimate administrative activity



## References

* hhttps://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1529/T1529.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_system_shutdown_reboot.yml))
```yaml
title: 'System Shutdown/Reboot'
id: 4cb57c2f-1f29-41f8-893d-8bed8e1c1d2f
status: test
description: 'Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.'
author: 'Igor Fits, oscd.community'
references:
  - hhttps://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1529/T1529.md
date: 2020/10/15
modified: 2021/11/27
logsource:
  product: linux
  service: auditd
detection:
  execve:
    type: 'EXECVE'
  shutdowncmd:
    - 'shutdown'
    - 'reboot'
    - 'halt'
    - 'poweroff'
  init:
    - 'init'
    - 'telinit'
  initselection:
    - '0'
    - '6'
  condition: execve and (shutdowncmd or (init and initselection))
falsepositives:
  - 'Legitimate administrative activity'
level: informational
tags:
  - attack.impact
  - attack.t1529

```
