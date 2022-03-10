---
title: "Suspicious PowerShell WindowStyle Option"
aliases:
  - "/rule/313fbb0a-a341-4682-848d-6d6f8c4fab7c"


tags:
  - attack.defense_evasion
  - attack.t1564.003



status: experimental





date: Wed, 20 Oct 2021 13:57:24 +0200


---

Adversaries may use hidden windows to conceal malicious activity from the plain sight of users. In some cases, windows that would typically be displayed when an application carries out an operation can be hidden

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_windowstyle.yml))
```yaml
title: Suspicious PowerShell WindowStyle Option
id: 313fbb0a-a341-4682-848d-6d6f8c4fab7c
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md
description: Adversaries may use hidden windows to conceal malicious activity from the plain sight of users. In some cases, windows that would typically be displayed when an application carries out an operation can be hidden
tags:
    - attack.defense_evasion
    - attack.t1564.003
author: frack113
date: 2021/10/20
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains|all: 
            - 'powershell'
            - 'WindowStyle'
            - 'Hidden'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
