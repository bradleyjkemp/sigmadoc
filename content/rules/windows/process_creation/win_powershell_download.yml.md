---
title: "PowerShell Download from URL"
aliases:
  - "/rule/3b6ab547-8ec2-4991-b9d2-2b06702a48d7"

tags:
  - attack.t1086
  - attack.execution
  - attack.t1059.001



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a Powershell process that contains download commands in its command line string

<!--more-->


## Known false-positives

* unknown




## Raw rule
```yaml
title: PowerShell Download from URL
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: experimental
description: Detects a Powershell process that contains download commands in its command line string
author: Florian Roth
date: 2019/01/16
tags:
    - attack.t1086  # an old one
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\powershell.exe'
        CommandLine:
            - '*new-object system.net.webclient).downloadstring(*'
            - '*new-object system.net.webclient).downloadfile(*'
            - '*new-object net.webclient).downloadstring(*'
            - '*new-object net.webclient).downloadfile(*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: medium

```
