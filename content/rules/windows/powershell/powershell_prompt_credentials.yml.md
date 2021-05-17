---
title: "PowerShell Credential Prompt"
aliases:
  - "/rule/ca8b77a9-d499-4095-b793-5d5f330d450e"

tags:
  - attack.credential_access
  - attack.execution
  - attack.t1059.001
  - attack.t1086



status: experimental



level: high



date: Sun, 9 Apr 2017 10:22:04 +0200


---

Detects PowerShell calling a credential prompt

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/JohnLaTwC/status/850381440629981184
* https://t.co/ezOTGy1a1G


## Raw rule
```yaml
title: PowerShell Credential Prompt
id: ca8b77a9-d499-4095-b793-5d5f330d450e
status: experimental
description: Detects PowerShell calling a credential prompt
references:
    - https://twitter.com/JohnLaTwC/status/850381440629981184
    - https://t.co/ezOTGy1a1G
tags:
    - attack.credential_access
    - attack.execution
    - attack.t1059.001
    - attack.t1086  # an old one
author: John Lambert (idea), Florian Roth (rule)
date: 2017/04/09
logsource:
    product: windows
    service: powershell
    definition: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
    keyword:
        Message:
            - '*PromptForCredential*'
    condition: all of them
falsepositives:
    - Unknown
level: high

```
