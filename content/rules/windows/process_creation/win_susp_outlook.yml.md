---
title: "Suspicious Execution from Outlook"
aliases:
  - "/rule/e212d415-0e93-435f-9e1a-f29005bb4723"

tags:
  - attack.execution
  - attack.t1059
  - attack.t1202



status: experimental



level: high



---

Detects EnableUnsafeClientMailRules used for Script Execution from Outlook

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/sensepost/ruler
* https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html


## Raw rule
```yaml
title: Suspicious Execution from Outlook
id: e212d415-0e93-435f-9e1a-f29005bb4723
status: experimental
description: Detects EnableUnsafeClientMailRules used for Script Execution from Outlook
references:
    - https://github.com/sensepost/ruler
    - https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html
tags:
    - attack.execution
    - attack.t1059
    - attack.t1202
author: Markus Neis
date: 2018/12/27
logsource:
    category: process_creation
    product: windows
detection:
    clientMailRules:
        CommandLine: '*EnableUnsafeClientMailRules*'
    outlookExec:
        ParentImage: '*\outlook.exe'
        CommandLine: \\\\*\\*.exe
    condition: clientMailRules or outlookExec
falsepositives:
    - unknown
level: high

```
