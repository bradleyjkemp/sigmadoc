---
title: "Bypass UAC via WSReset.exe"
aliases:
  - "/rule/d797268e-28a9-49a7-b9a8-2f5039011c5c"


tags:
  - attack.privilege_escalation
  - attack.t1548.002



status: test





date: Mon, 28 Oct 2019 11:59:49 +0100


---

Identifies use of WSReset.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.

<!--more-->


## Known false-positives

* Unknown



## References

* https://eqllib.readthedocs.io/en/latest/analytics/532b5ed4-7930-11e9-8f5c-d46d6d62a49e.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uac_wsreset.yml))
```yaml
title: Bypass UAC via WSReset.exe
id: d797268e-28a9-49a7-b9a8-2f5039011c5c
status: test
description: Identifies use of WSReset.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.
author: E.M. Anhaus (originally from Atomic Blue Detections, Tony Lambert), oscd.community
references:
  - https://eqllib.readthedocs.io/en/latest/analytics/532b5ed4-7930-11e9-8f5c-d46d6d62a49e.html
date: 2019/10/24
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\wsreset.exe'
  filter:
    Image|endswith: '\conhost.exe'
  condition: selection and not filter
falsepositives:
  - Unknown
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548.002

```
