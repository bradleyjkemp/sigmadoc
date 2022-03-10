---
title: "PowerShell Called from an Executable Version Mismatch"
aliases:
  - "/rule/c70e019b-1479-4b65-b0cc-cd0c6093a599"


tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1059.001



status: experimental





date: Sun, 5 Mar 2017 01:47:25 +0100


---

Detects PowerShell called from an executable by the version mismatch method

<!--more-->


## Known false-positives

* Penetration Tests
* Unknown



## References

* https://adsecurity.org/?p=2921


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml))
```yaml
title: PowerShell Called from an Executable Version Mismatch
id: c70e019b-1479-4b65-b0cc-cd0c6093a599
status: experimental
description: Detects PowerShell called from an executable by the version mismatch method
references:
    - https://adsecurity.org/?p=2921
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1059.001
author: Sean Metcalf (source), Florian Roth (rule)
date: 2017/03/05
modified: 2021/10/16
logsource:
    product: windows
    category: ps_classic_start
    definition: fields have to be extract from event
detection:
    selection1:
        EngineVersion|startswith:
            - '2.'
            - '4.'
            - '5.'
        HostVersion|startswith: '3.'
    condition: selection1
falsepositives:
    - Penetration Tests
    - Unknown
level: high

```
