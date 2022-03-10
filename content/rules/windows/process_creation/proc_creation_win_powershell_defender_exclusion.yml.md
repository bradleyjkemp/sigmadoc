---
title: "Powershell Defender Exclusion"
aliases:
  - "/rule/17769c90-230e-488b-a463-e05c08e9d48f"


tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects requests to exclude files, folders or processes from Antivirus scanning using PowerShell cmdlets

<!--more-->


## Known false-positives

* Possible Admin Activity
* Other Cmdlets that may use the same parameters



## References

* https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-process-opened-file-exclusions-microsoft-defender-antivirus
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md
* https://twitter.com/AdamTheAnalyst/status/1483497517119590403


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_powershell_defender_exclusion.yml))
```yaml
title: Powershell Defender Exclusion
id: 17769c90-230e-488b-a463-e05c08e9d48f
status: experimental
description: Detects requests to exclude files, folders or processes from Antivirus scanning using PowerShell cmdlets
references:
    - https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-process-opened-file-exclusions-microsoft-defender-antivirus
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md
    - https://twitter.com/AdamTheAnalyst/status/1483497517119590403
tags:
    - attack.defense_evasion
    - attack.t1562.001
author: Florian Roth
date: 2021/04/29
modified: 2022/03/04
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains: 
            - 'Add-MpPreference '
            - 'Set-MpPreference '
    selection2:
        CommandLine|contains:
            - ' -ExclusionPath '
            - ' -ExclusionExtension '
            - ' -ExclusionProcess '
    condition: all of selection*
falsepositives:
    - Possible Admin Activity
    - Other Cmdlets that may use the same parameters
level: medium

```
