---
title: "Suspicious Start-Process PassThru"
aliases:
  - "/rule/0718cd72-f316-4aa2-988f-838ea8533277"


tags:
  - attack.defense_evasion
  - attack.t1036.003



status: experimental





date: Sat, 15 Jan 2022 17:04:03 +0100


---

Powershell use PassThru option to start in background

<!--more-->


## Known false-positives

* Legitimate PowerShell scripts



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.md
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/Start-Process?view=powershell-5.1&viewFallbackFrom=powershell-7


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_start_process.yml))
```yaml
title: Suspicious Start-Process PassThru
id: 0718cd72-f316-4aa2-988f-838ea8533277
status: experimental
description: Powershell use PassThru option to start in background
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.md
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/Start-Process?view=powershell-5.1&viewFallbackFrom=powershell-7
date: 2022/01/15
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains|all:
            - Start-Process
            - '-PassThru '
            - '-FilePath '
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: medium
tags:
    - attack.defense_evasion
    - attack.t1036.003

```
