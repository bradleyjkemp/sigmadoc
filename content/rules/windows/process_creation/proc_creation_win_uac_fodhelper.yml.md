---
title: "Bypass UAC via Fodhelper.exe"
aliases:
  - "/rule/7f741dcf-fc22-4759-87b4-9ae8376676a2"
ruleid: 7f741dcf-fc22-4759-87b4-9ae8376676a2

tags:
  - attack.privilege_escalation
  - attack.t1548.002



status: test





date: Mon, 28 Oct 2019 11:59:49 +0100


---

Identifies use of Fodhelper.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.

<!--more-->


## Known false-positives

* Legitimate use of fodhelper.exe utility by legitimate user



## References

* https://eqllib.readthedocs.io/en/latest/analytics/e491ce22-792f-11e9-8f5c-d46d6d62a49e.html
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1088/T1088.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uac_fodhelper.yml))
```yaml
title: Bypass UAC via Fodhelper.exe
id: 7f741dcf-fc22-4759-87b4-9ae8376676a2
status: test
description: Identifies use of Fodhelper.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.
author: E.M. Anhaus (originally from Atomic Blue Detections, Tony Lambert), oscd.community
references:
  - https://eqllib.readthedocs.io/en/latest/analytics/e491ce22-792f-11e9-8f5c-d46d6d62a49e.html
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1088/T1088.md
date: 2019/10/24
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\fodhelper.exe'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
falsepositives:
  - Legitimate use of fodhelper.exe utility by legitimate user
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548.002

```