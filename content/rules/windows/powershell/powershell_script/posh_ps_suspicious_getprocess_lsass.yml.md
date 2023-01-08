---
title: "PowerShell Get-Process LSASS in ScriptBlock"
aliases:
  - "/rule/84c174ab-d3ef-481f-9c86-a50d0b8e3edb"
ruleid: 84c174ab-d3ef-481f-9c86-a50d0b8e3edb

tags:
  - attack.credential_access
  - attack.t1003.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a Get-Process command on lsass process, which is in almost all cases a sign of malicious activity

<!--more-->


## Known false-positives

* Legitimate certificate exports invoked by administrators or users (depends on processes in the environment - filter if unusable)



## References

* https://twitter.com/PythonResponder/status/1385064506049630211


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_getprocess_lsass.yml))
```yaml
title: PowerShell Get-Process LSASS in ScriptBlock
id: 84c174ab-d3ef-481f-9c86-a50d0b8e3edb
status: experimental
description: Detects a Get-Process command on lsass process, which is in almost all cases a sign of malicious activity
references:
    - https://twitter.com/PythonResponder/status/1385064506049630211
tags:
    - attack.credential_access
    - attack.t1003.001
author: Florian Roth
date: 2021/04/23
modified: 2021/10/16
logsource:
    product: windows
    category: ps_script
    definition: Script Block Logging must be enable
detection:
    select_LSASS:
        ScriptBlockText|contains: 'Get-Process lsass'
    condition: select_LSASS
falsepositives:
    - Legitimate certificate exports invoked by administrators or users (depends on processes in the environment - filter if unusable)
level: high

```
