---
title: "Suspicious PowerShell Invocation Based on Parent Process"
aliases:
  - "/rule/95eadcb2-92e4-4ed1-9031-92547773a6db"

tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1086



status: experimental



level: medium



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious powershell invocations from interpreters or unusual programs

<!--more-->


## Known false-positives

* Microsoft Operations Manager (MOM)
* Other scripts



## References

* https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/


## Raw rule
```yaml
title: Suspicious PowerShell Invocation Based on Parent Process
id: 95eadcb2-92e4-4ed1-9031-92547773a6db
status: experimental
description: Detects suspicious powershell invocations from interpreters or unusual programs
author: Florian Roth
date: 2019/01/16
references:
    - https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\wscript.exe'
            - '*\cscript.exe'
        Image:
            - '*\powershell.exe'
    falsepositive:
        CurrentDirectory: '*\Health Service State\\*'
    condition: selection and not falsepositive
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Microsoft Operations Manager (MOM)
    - Other scripts
level: medium

```
