---
title: "Registry Defender Exclusions"
aliases:
  - "/rule/48917adc-a28e-4f5d-b729-11e75da8941f"
ruleid: 48917adc-a28e-4f5d-b729-11e75da8941f

tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Sun, 13 Feb 2022 16:07:28 +0100


---

Qbot used reg.exe to add Defender folder exceptions for folders within AppData and ProgramData.

<!--more-->


## Known false-positives

* legitimate use



## References

* https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
* https://redcanary.com/threat-detection-report/threats/qbot/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_reg_defender_exclusion.yml))
```yaml
title: Registry Defender Exclusions
id: 48917adc-a28e-4f5d-b729-11e75da8941f
status: experimental
description: Qbot used reg.exe to add Defender folder exceptions for folders within AppData and ProgramData.
references:
    - https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
    - https://redcanary.com/threat-detection-report/threats/qbot/
author: frack113
date: 2022/02/13
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \reg.exe
        CommandLine|contains:
            - 'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\'
            - 'HKLM\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Paths'
        CommandLine|contains|all:
            - 'ADD '
            - '/t '
            - 'REG_DWORD '
            - '/v '
            - '/d '
            - '0'
    condition: selection
falsepositives:
    - legitimate use
level: medium
tags:
    - attack.defense_evasion
    - attack.t1562.001 

```