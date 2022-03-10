---
title: "Windows Defender Threat Detection Disabled"
aliases:
  - "/rule/fe34868f-6e0e-4882-81f6-c43aa8f15b62"


tags:
  - attack.defense_evasion
  - attack.t1562.001



status: stable





date: Sun, 28 Jun 2020 10:55:32 +0200


---

Detects disabling Windows Defender threat protection

<!--more-->


## Known false-positives

* Administrator actions



## References

* https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/windefend/win_defender_disabled.yml))
```yaml
title: Windows Defender Threat Detection Disabled
id: fe34868f-6e0e-4882-81f6-c43aa8f15b62
description: Detects disabling Windows Defender threat protection
date: 2020/07/28
modified: 2021/09/21
author: Ján Trenčanský, frack113
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md
status: stable
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID:
            - 5001
            - 5010
            - 5012
            - 5101
    condition: selection
falsepositives:
    - Administrator actions
level: high
```
