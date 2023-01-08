---
title: "Execute Files with Msdeploy.exe"
aliases:
  - "/rule/646bc99f-6682-4b47-a73a-17b1b64c9d34"
ruleid: 646bc99f-6682-4b47-a73a-17b1b64c9d34

tags:
  - attack.execution
  - attack.t1218



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects file execution using the msdeploy.exe lolbin

<!--more-->


## Known false-positives

* System administrator Usage
* Penetration test



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Msdeploy.yml
* https://twitter.com/pabraeken/status/995837734379032576
* https://twitter.com/pabraeken/status/999090532839313408


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_msdeploy.yml))
```yaml
title: Execute Files with Msdeploy.exe
id: 646bc99f-6682-4b47-a73a-17b1b64c9d34
status: test
description: Detects file execution using the msdeploy.exe lolbin
author: Beyu Denis, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Msdeploy.yml
  - https://twitter.com/pabraeken/status/995837734379032576
  - https://twitter.com/pabraeken/status/999090532839313408
date: 2020/10/18
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'verb:sync'
      - '-source:RunCommand'
      - '-dest:runCommand'
    Image|endswith:
      - '\msdeploy.exe'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
  - ParentCommandLine
falsepositives:
  - System administrator Usage
  - Penetration test
level: medium
tags:
  - attack.execution
  - attack.t1218

```
