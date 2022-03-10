---
title: "Systemd Service Reload or Start"
aliases:
  - "/rule/2625cc59-0634-40d0-821e-cb67382a3dd7"


tags:
  - attack.persistence
  - attack.t1543.002



status: test





date: Wed, 23 Oct 2019 11:21:19 -0700


---

Detects a reload or a start of a service.

<!--more-->


## Known false-positives

* Installation of legitimate service.
* Legitimate reconfiguration of service.



## References

* https://attack.mitre.org/techniques/T1543/002/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_pers_systemd_reload.yml))
```yaml
title: Systemd Service Reload or Start
id: 2625cc59-0634-40d0-821e-cb67382a3dd7
status: test
description: Detects a reload or a start of a service.
author: Jakob Weinzettl, oscd.community
references:
  - https://attack.mitre.org/techniques/T1543/002/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md
date: 2019/09/23
modified: 2021/11/27
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: 'EXECVE'
    a0|contains: 'systemctl'
    a1|contains:
      - 'daemon-reload'
      - 'start'
  condition: selection
falsepositives:
  - Installation of legitimate service.
  - Legitimate reconfiguration of service.
level: low
tags:
  - attack.persistence
  - attack.t1543.002

```
