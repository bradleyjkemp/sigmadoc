---
title: "Suspicious PowerShell Invocations - Generic"
aliases:
  - "/rule/3d304fda-78aa-43ed-975c-d740798a49c1"

tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1086



status: experimental



level: high



date: Sun, 12 Mar 2017 17:06:53 +0100


---

Detects suspicious PowerShell invocation command parameters

<!--more-->


## Known false-positives

* Penetration tests
* Very special / sneaky PowerShell scripts




## Raw rule
```yaml
title: Suspicious PowerShell Invocations - Generic
id: 3d304fda-78aa-43ed-975c-d740798a49c1
status: experimental
description: Detects suspicious PowerShell invocation command parameters
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086  #an old one
author: Florian Roth (rule)
date: 2017/03/12
logsource:
    product: windows
    service: powershell
detection:
    encoded:
        - ' -enc '
        - ' -EncodedCommand '
    hidden:
        - ' -w hidden '
        - ' -window hidden '
        - ' -windowstyle hidden '
    noninteractive:
        - ' -noni '
        - ' -noninteractive '
    condition: all of them
falsepositives:
    - Penetration tests
    - Very special / sneaky PowerShell scripts
level: high

```
