---
title: "Suspicious Encoded PowerShell Command Line"
aliases:
  - "/rule/ca2092a1-c273-4878-9b4b-0d60115bf5ea"

tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1086



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)

<!--more-->




## References

* https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e


## Raw rule
```yaml
title: Suspicious Encoded PowerShell Command Line
id: ca2092a1-c273-4878-9b4b-0d60115bf5ea
description: Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)
status: experimental
references:
    - https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e
author: Florian Roth, Markus Neis
date: 2018/09/03
modified: 2020/10/20
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -e JAB*'
            - '* -e  JAB*'
            - '* -e   JAB*'
            - '* -e    JAB*'
            - '* -e     JAB*'
            - '* -e      JAB*'
            - '* -en JAB*'
            - '* -enc JAB*'
            - '* -enc* JAB*'
            - '* -w hidden -e* JAB*'
            - '* BA^J e-'
            - '* -e SUVYI*'
            - '* -e aWV4I*'
            - '* -e SQBFAFgA*'
            - '* -e aQBlAHgA*'
            - '* -enc SUVYI*'
            - '* -enc aWV4I*'
            - '* -enc SQBFAFgA*'
            - '* -enc aQBlAHgA*'
            - '* -e* IAA*'
            - '* -e* IAB*'
            - '* -e* UwB*'
            - '* -e* cwB*'
            - '*.exe -ENCOD *'
    falsepositive1:
        CommandLine: '* -ExecutionPolicy remotesigned *'
    condition: selection and not falsepositive1
level: high

```
