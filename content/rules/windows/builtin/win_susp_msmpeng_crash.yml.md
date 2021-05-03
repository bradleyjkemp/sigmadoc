---
title: "Microsoft Malware Protection Engine Crash"
aliases:
  - "/rule/6c82cf5c-090d-4d57-9188-533577631108"

tags:
  - attack.defense_evasion
  - attack.t1089
  - attack.t1211
  - attack.t1562.001



date: Tue, 9 May 2017 22:46:57 +0200


---

This rule detects a suspicious crash of the Microsoft Malware Protection Engine

<!--more-->


## Known false-positives

* MsMpEng.exe can crash when C:\ is full



## References

* https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5
* https://technet.microsoft.com/en-us/library/security/4022344


## Raw rule
```yaml
title: Microsoft Malware Protection Engine Crash
id: 6c82cf5c-090d-4d57-9188-533577631108
description: This rule detects a suspicious crash of the Microsoft Malware Protection Engine
tags:
    - attack.defense_evasion
    - attack.t1089          # an old one
    - attack.t1211
    - attack.t1562.001
status: experimental
date: 2017/05/09
references:
    - https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5
    - https://technet.microsoft.com/en-us/library/security/4022344
author: Florian Roth
logsource:
    product: windows
    service: application
detection:
    selection1:
        Source: 'Application Error'
        EventID: 1000
    selection2:
        Source: 'Windows Error Reporting'
        EventID: 1001
    keywords:
        Message:
            - '*MsMpEng.exe*'
            - '*mpengine.dll*'
    condition: 1 of selection* and all of keywords
falsepositives:
    - MsMpEng.exe can crash when C:\ is full
level: high

```