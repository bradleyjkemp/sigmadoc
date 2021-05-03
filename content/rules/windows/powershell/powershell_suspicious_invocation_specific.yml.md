---
title: "Suspicious PowerShell Invocations - Specific"
aliases:
  - "/rule/fce5f582-cc00-41e1-941a-c6fabf0fdb8c"

tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1086



date: Sun, 5 Mar 2017 15:01:51 +0100


---

Detects suspicious PowerShell invocation command parameters

<!--more-->


## Known false-positives

* Penetration tests




## Raw rule
```yaml
title: Suspicious PowerShell Invocations - Specific
id: fce5f582-cc00-41e1-941a-c6fabf0fdb8c
status: experimental
description: Detects suspicious PowerShell invocation command parameters
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086  #an old one
author: Florian Roth (rule)
date: 2017/03/05
logsource:
    product: windows
    service: powershell
detection:
    keywords:
        Message:
            - '* -nop -w hidden -c * [Convert]::FromBase64String*'
            - '* -w hidden -noni -nop -c "iex(New-Object*'
            - '* -w hidden -ep bypass -Enc*'
            - '*powershell.exe reg add HKCU\software\microsoft\windows\currentversion\run*'
            - '*bypass -noprofile -windowstyle hidden (new-object system.net.webclient).download*'
            - '*iex(New-Object Net.WebClient).Download*'
    condition: keywords
falsepositives:
    - Penetration tests
level: high

```
