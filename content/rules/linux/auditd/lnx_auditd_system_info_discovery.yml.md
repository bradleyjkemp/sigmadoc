---
title: "System Information Discovery"
aliases:
  - "/rule/f34047d9-20d3-4e8b-8672-0a35cc50dc71"
ruleid: f34047d9-20d3-4e8b-8672-0a35cc50dc71

tags:
  - attack.discovery
  - attack.t1082



status: experimental





date: Fri, 3 Sep 2021 11:33:18 +0200


---

Detects System Information Discovery commands

<!--more-->


## Known false-positives

* Legitimate administrative activity



## References

* https://attack.mitre.org/techniques/T1082/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_system_info_discovery.yml))
```yaml
title: System Information Discovery
id: f34047d9-20d3-4e8b-8672-0a35cc50dc71
description: Detects System Information Discovery commands
author: 'Pawel Mazur'
status: experimental
date: 2021/09/03
references:
   - https://attack.mitre.org/techniques/T1082/
   - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md
logsource:
   product: linux
   service: auditd
detection:
   selection:
       type: PATH
       name:
           - /etc/lsb-release
           - /etc/redhat-release
           - /etc/issue
   selection2:
       type: EXECVE
       a0:
           - uname
           - uptime
   condition: selection or selection2
tags:
   - attack.discovery
   - attack.t1082
falsepositives:
   - Legitimate administrative activity
level: low

```
