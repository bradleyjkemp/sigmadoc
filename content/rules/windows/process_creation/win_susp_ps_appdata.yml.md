---
title: "PowerShell Script Run in AppData"
aliases:
  - "/rule/ac175779-025a-4f12-98b0-acdaeb77ea85"

tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1086



status: experimental



level: medium



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder

<!--more-->


## Known false-positives

* Administrative scripts



## References

* https://twitter.com/JohnLaTwC/status/1082851155481288706
* https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03


## Raw rule
```yaml
title: PowerShell Script Run in AppData
id: ac175779-025a-4f12-98b0-acdaeb77ea85
status: experimental
description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder
references:
    - https://twitter.com/JohnLaTwC/status/1082851155481288706
    - https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086      # an old one     
author: Florian Roth
date: 2019/01/09
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* /c powershell*\AppData\Local\\*'
            - '* /c powershell*\AppData\Roaming\\*'
    condition: selection
falsepositives:
    - Administrative scripts
level: medium

```
