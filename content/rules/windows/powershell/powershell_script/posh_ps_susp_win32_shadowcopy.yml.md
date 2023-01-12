---
title: "Delete Volume Shadow Copies via WMI with PowerShell"
aliases:
  - "/rule/e17121b4-ef2a-4418-8a59-12fb1631fa9e"
ruleid: e17121b4-ef2a-4418-8a59-12fb1631fa9e

tags:
  - attack.impact
  - attack.t1490



status: test





date: Sun, 26 Dec 2021 12:09:42 +0100


---

Deletes Windows Volume Shadow Copies with PowerShell code and Get-WMIObject. This technique is used by numerous ransomware families such as Sodinokibi/REvil

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-5---windows---delete-volume-shadow-copies-via-wmi-with-powershell


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_susp_win32_shadowcopy.yml))
```yaml
title: Delete Volume Shadow Copies via WMI with PowerShell
id: e17121b4-ef2a-4418-8a59-12fb1631fa9e
status: test
author: frack113
date: 2021/12/26
description: Deletes Windows Volume Shadow Copies with PowerShell code and Get-WMIObject. This technique is used by numerous ransomware families such as Sodinokibi/REvil
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-5---windows---delete-volume-shadow-copies-via-wmi-with-powershell
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Get-WmiObject'
            - 'Win32_Shadowcopy'
            - '.Delete()' 
    condition: selection
falsepositives:
    - Unknown
level: high
tags:
    - attack.impact
    - attack.t1490

```