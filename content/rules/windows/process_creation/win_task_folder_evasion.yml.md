---
title: "Tasks Folder Evasion"
aliases:
  - "/rule/cc4e02ba-9c06-48e2-b09e-2500cace9ae0"

tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.execution
  - attack.t1574.002
  - attack.t1059
  - attack.t1064



date: Mon, 13 Jan 2020 13:21:06 +0800


---

The Tasks folder in system32 and syswow64 are globally writable paths. Adversaries can take advantage of this and load or influence any script hosts or ANY .NET Application in Tasks to load and execute a custom assembly into cscript, wscript, regsvr32, mshta, eventvwr

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/subTee/status/1216465628946563073
* https://gist.github.com/am0nsec/8378da08f848424e4ab0cc5b317fdd26


## Raw rule
```yaml
title: Tasks Folder Evasion
id: cc4e02ba-9c06-48e2-b09e-2500cace9ae0
status: experimental
description: The Tasks folder in system32 and syswow64 are globally writable paths. Adversaries can take advantage of this and load or influence any script hosts or ANY .NET Application in Tasks to load and execute a custom assembly into cscript, wscript, regsvr32, mshta, eventvwr
references:
    - https://twitter.com/subTee/status/1216465628946563073
    - https://gist.github.com/am0nsec/8378da08f848424e4ab0cc5b317fdd26
date: 2020/01/13
modified: 2020/08/29
author: Sreeman
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.execution
    - attack.t1574.002
    - attack.t1059  # an old one
    - attack.t1064  # an old one

logsource:
    product: Windows
detection:
    selection1:
        CommandLine|contains:
            - 'echo '
            - 'copy '
            - 'type '
            - 'file createnew'
    selection2:
        CommandLine|contains:
            - ' C:\Windows\System32\Tasks\'
            - ' C:\Windows\SysWow64\Tasks\'
    condition: selection1 and selection2
fields:
    - CommandLine
    - ParentProcess
falsepositives:
    - Unknown
level: high

```