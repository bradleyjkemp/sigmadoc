---
title: "Powershell AMSI Bypass via .NET Reflection"
aliases:
  - "/rule/30edb182-aa75-42c0-b0a9-e998bb29067c"

tags:
  - attack.defense_evasion
  - attack.t1089
  - attack.t1562.001



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects Request to amsiInitFailed that can be used to disable AMSI Scanning

<!--more-->


## Known false-positives

* Potential Admin Activity



## References

* https://twitter.com/mattifestation/status/735261176745988096
* https://www.hybrid-analysis.com/sample/0ced17419e01663a0cd836c9c2eb925e3031ffb5b18ccf35f4dea5d586d0203e?environmentId=120


## Raw rule
```yaml
title: Powershell AMSI Bypass via .NET Reflection
id: 30edb182-aa75-42c0-b0a9-e998bb29067c
status: experimental
description: Detects Request to amsiInitFailed that can be used to disable AMSI Scanning
references:
    - https://twitter.com/mattifestation/status/735261176745988096
    - https://www.hybrid-analysis.com/sample/0ced17419e01663a0cd836c9c2eb925e3031ffb5b18ccf35f4dea5d586d0203e?environmentId=120
tags:
    - attack.defense_evasion
    - attack.t1089         # an old one
    - attack.t1562.001
author: Markus Neis
date: 2018/08/17
modified: 2020/09/01
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '*System.Management.Automation.AmsiUtils*'
    selection2:
        CommandLine:
            - '*amsiInitFailed*'
    condition: selection1 and selection2
falsepositives:
    - Potential Admin Activity
level: high

```