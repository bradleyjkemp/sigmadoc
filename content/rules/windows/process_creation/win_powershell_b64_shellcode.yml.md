---
title: "PowerShell Base64 Encoded Shellcode"
aliases:
  - "/rule/2d117e49-e626-4c7c-bd1f-c3c0147774c8"

tags:
  - attack.defense_evasion
  - attack.t1027



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects Base64 encoded Shellcode

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/cyb3rops/status/1063072865992523776


## Raw rule
```yaml
title: PowerShell Base64 Encoded Shellcode
id: 2d117e49-e626-4c7c-bd1f-c3c0147774c8
description: Detects Base64 encoded Shellcode
status: experimental
references:
    - https://twitter.com/cyb3rops/status/1063072865992523776
author: Florian Roth
date: 2018/11/17
modified: 2020/09/01
tags:
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine: '*AAAAYInlM*'
    selection2:
        CommandLine:
            - '*OiCAAAAYInlM*'
            - '*OiJAAAAYInlM*'
    condition: selection1 and selection2
falsepositives:
    - Unknown
level: critical

```
