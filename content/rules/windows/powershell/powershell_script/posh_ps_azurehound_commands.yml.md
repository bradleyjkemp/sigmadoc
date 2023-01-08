---
title: "AzureHound PowerShell Commands"
aliases:
  - "/rule/83083ac6-1816-4e76-97d7-59af9a9ae46e"
ruleid: 83083ac6-1816-4e76-97d7-59af9a9ae46e

tags:
  - attack.discovery
  - attack.t1482
  - attack.t1087
  - attack.t1087.001
  - attack.t1087.002
  - attack.t1069.001
  - attack.t1069.002
  - attack.t1069



status: experimental





date: Sat, 23 Oct 2021 18:27:36 -0500


---

Detects the execution of AzureHound in PowerShell, a tool to gather data from Azure for BloodHound

<!--more-->


## Known false-positives

* Penetration testing



## References

* https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/AzureHound.ps1
* https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_azurehound_commands.yml))
```yaml
title: AzureHound PowerShell Commands
id: 83083ac6-1816-4e76-97d7-59af9a9ae46e
status: experimental
description: Detects the execution of AzureHound in PowerShell, a tool to gather data from Azure for BloodHound
references:
    - https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/AzureHound.ps1
    - https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html
author: Austin Songer (@austinsonger)
date: 2021/10/23
modified: 2022/01/12
logsource:
    product: windows
    category: ps_script
    definition: Script Block Logging must be enabled
detection:
    selection:
        ScriptBlockText|contains: Invoke-AzureHound
    condition: selection
tags:
    - attack.discovery
    - attack.t1482
    - attack.t1087
    - attack.t1087.001
    - attack.t1087.002
    - attack.t1069.001
    - attack.t1069.002
    - attack.t1069
falsepositives:
    - Penetration testing
level: high

```
