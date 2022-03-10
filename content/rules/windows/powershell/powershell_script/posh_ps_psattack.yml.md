---
title: "PowerShell PSAttack"
aliases:
  - "/rule/b7ec41a4-042c-4f31-a5db-d0fcde9fa5c5"


tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Sun, 5 Mar 2017 01:47:25 +0100


---

Detects the use of PSAttack PowerShell hack tool

<!--more-->


## Known false-positives

* Pentesters



## References

* https://adsecurity.org/?p=2921


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_psattack.yml))
```yaml
title: PowerShell PSAttack
id: b7ec41a4-042c-4f31-a5db-d0fcde9fa5c5
status: experimental
description: Detects the use of PSAttack PowerShell hack tool
references:
    - https://adsecurity.org/?p=2921
tags:
    - attack.execution
    - attack.t1059.001
author: Sean Metcalf (source), Florian Roth (rule)
date: 2017/03/05
modified: 2021/10/16
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains: 'PS ATTACK!!!'
    condition: selection
falsepositives:
    - Pentesters
level: high

```
