---
title: "UAC Bypass Using Consent and Comctl32 - Process"
aliases:
  - "/rule/1ca6bd18-0ba0-44ca-851c-92ed89a61085"
ruleid: 1ca6bd18-0ba0-44ca-851c-92ed89a61085

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uac_bypass_consent_comctl32.yml))
```yaml
title: UAC Bypass Using Consent and Comctl32 - Process
id: 1ca6bd18-0ba0-44ca-851c-92ed89a61085
description: Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)
author: Christian Burkard
date: 2021/08/23
status: experimental
references:
    - https://github.com/hfiref0x/UACME
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\consent.exe'
        Image|endswith: '\werfault.exe'
        IntegrityLevel:
          - 'High'
          - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high

```
