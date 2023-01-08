---
title: "PowerShell Get-Process LSASS"
aliases:
  - "/rule/b2815d0d-7481-4bf0-9b6c-a4c48a94b349"
ruleid: b2815d0d-7481-4bf0-9b6c-a4c48a94b349

tags:
  - attack.credential_access
  - attack.t1552.004



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a Get-Process command on lsass process, which is in almost all cases a sign of malicious activity

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/PythonResponder/status/1385064506049630211


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_powershell_getprocess_lsass.yml))
```yaml
title: PowerShell Get-Process LSASS
id: b2815d0d-7481-4bf0-9b6c-a4c48a94b349
description: Detects a Get-Process command on lsass process, which is in almost all cases a sign of malicious activity
status: experimental
references:
    - https://twitter.com/PythonResponder/status/1385064506049630211
author: Florian Roth
date: 2021/04/23
tags:
    - attack.credential_access
    - attack.t1552.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'Get-Process lsass'
    condition: selection
falsepositives: 
    - Unknown
level: high

```
