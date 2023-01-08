---
title: "Code Executed Via Office Add-in XLL File"
aliases:
  - "/rule/36fbec91-fa1b-4d5d-8df1-8d8edcb632ad"
ruleid: 36fbec91-fa1b-4d5d-8df1-8d8edcb632ad

tags:
  - attack.persistence
  - attack.t1137.006



status: experimental





date: Wed, 29 Dec 2021 17:47:43 +0100


---

Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system.
Office add-ins can be used to add functionality to Office programs


<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.006/T1137.006.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_office_comobject_registerxll.yml))
```yaml
title: Code Executed Via Office Add-in XLL File
id: 36fbec91-fa1b-4d5d-8df1-8d8edcb632ad
status: experimental
description: |
  Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system.
  Office add-ins can be used to add functionality to Office programs
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.006/T1137.006.md
author: frack113
date: 2021/12/28
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'new-object '
            - '-ComObject '
            - '.application'
            - '.RegisterXLL'
    condition: selection
falsepositives:
    - unknown
level: high
tags:
    - attack.persistence
    - attack.t1137.006

```
