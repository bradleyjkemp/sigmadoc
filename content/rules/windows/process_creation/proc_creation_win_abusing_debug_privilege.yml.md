---
title: "Abused Debug Privilege by Arbitrary Parent Processes"
aliases:
  - "/rule/d522eca2-2973-4391-a3e0-ef0374321dae"


tags:
  - attack.privilege_escalation
  - attack.t1548



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detection of unusual child processes by different system processes

<!--more-->


## Known false-positives

* unknown



## References

* https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-74-638.jpg


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_abusing_debug_privilege.yml))
```yaml
title: Abused Debug Privilege by Arbitrary Parent Processes
id: d522eca2-2973-4391-a3e0-ef0374321dae
status: test
description: Detection of unusual child processes by different system processes
author: 'Semanur Guneysu @semanurtg, oscd.community'
references:
  - https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-74-638.jpg
date: 2020/10/28
modified: 2021/11/27
logsource:
  product: windows
  category: process_creation
detection:
  selection1:
    ParentImage|endswith:
      - '\winlogon.exe'
      - '\services.exe'
      - '\lsass.exe'
      - '\csrss.exe'
      - '\smss.exe'
      - '\wininit.exe'
      - '\spoolsv.exe'
      - '\searchindexer.exe'
  selection2:
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
  selection3:
    User|startswith:
      - 'NT AUTHORITY\SYSTEM'
      - 'AUTORITE NT\Sys'           # French language settings
  filter:
    CommandLine|contains|all:
      - ' route '
      - ' ADD '
  condition: selection1 and selection2 and selection3 and not filter
fields:
  - ParentImage
  - Image
  - User
  - CommandLine
falsepositives:
  - unknown
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548

```