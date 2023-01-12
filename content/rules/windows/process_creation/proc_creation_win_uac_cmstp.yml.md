---
title: "Bypass UAC via CMSTP"
aliases:
  - "/rule/e66779cc-383e-4224-a3a4-267eeb585c40"
ruleid: e66779cc-383e-4224-a3a4-267eeb585c40

tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1548.002
  - attack.t1218.003



status: test





date: Mon, 28 Oct 2019 11:59:49 +0100


---

Detect child processes of automatically elevated instances of Microsoft Connection Manager Profile Installer (cmstp.exe).

<!--more-->


## Known false-positives

* Legitimate use of cmstp.exe utility by legitimate user



## References

* https://eqllib.readthedocs.io/en/latest/analytics/e584f1a1-c303-4885-8a66-21360c90995b.html
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1191/T1191.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uac_cmstp.yml))
```yaml
title: Bypass UAC via CMSTP
id: e66779cc-383e-4224-a3a4-267eeb585c40
status: test
description: Detect child processes of automatically elevated instances of Microsoft Connection Manager Profile Installer (cmstp.exe).
author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
references:
  - https://eqllib.readthedocs.io/en/latest/analytics/e584f1a1-c303-4885-8a66-21360c90995b.html
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1191/T1191.md
date: 2019/10/24
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cmstp.exe'
    CommandLine|contains:
      - '/s'
      - '/au'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
falsepositives:
  - Legitimate use of cmstp.exe utility by legitimate user
level: high
tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1548.002
  - attack.t1218.003

```