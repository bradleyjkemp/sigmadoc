---
title: "Microsoft Defender Tamper Protection Trigger"
aliases:
  - "/rule/49e5bc24-8b86-49f1-b743-535f332c2856"


tags:
  - attack.defense_evasion
  - attack.t1562.001



status: stable





date: Mon, 5 Jul 2021 20:30:07 +0545


---

Detects block of attempt to disable real time protection of Microsoft Defender by tamper protection

<!--more-->


## Known false-positives

* Administrator actions



## References

* https://bhabeshraj.com/post/tampering-with-microsoft-defenders-tamper-protection


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/windefend/win_defender_tamper_protection_trigger.yml))
```yaml
title: Microsoft Defender Tamper Protection Trigger
id: 49e5bc24-8b86-49f1-b743-535f332c2856
description: Detects block of attempt to disable real time protection of Microsoft Defender by tamper protection
date: 2021/07/05
author: Bhabesh Raj
references:
    - https://bhabeshraj.com/post/tampering-with-microsoft-defenders-tamper-protection
status: stable
tags:
    - attack.defense_evasion
    - attack.t1562.001
falsepositives:
    - Administrator actions
level: critical
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID:
            - 5013
        Value|endswith:
            - '\Windows Defender\DisableAntiSpyware = 0x1()'
            - '\Real-Time Protection\DisableRealtimeMonitoring = (Current)'
    condition: selection
```
