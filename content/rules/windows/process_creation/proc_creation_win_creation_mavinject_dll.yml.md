---
title: "Mavinject Inject DLL Into Running Process"
aliases:
  - "/rule/4f73421b-5a0b-4bbf-a892-5a7fb99bea66"


tags:
  - attack.defense_evasion
  - attack.collection
  - attack.t1218
  - attack.t1056.004



status: experimental





date: Mon, 12 Jul 2021 16:08:18 +0200


---

Injects arbitrary DLL into running process specified by process ID. Requires Windows 10.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.004/T1056.004.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_creation_mavinject_dll.yml))
```yaml
title: Mavinject Inject DLL Into Running Process
id: 4f73421b-5a0b-4bbf-a892-5a7fb99bea66
status: experimental
author: frack113
date: 2021/07/12
description: Injects arbitrary DLL into running process specified by process ID. Requires Windows 10.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.004/T1056.004.md
tags:
    - attack.defense_evasion
    - attack.collection
    - attack.t1218
    - attack.t1056.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - ' /INJECTRUNNING'
            - '.dll' # space some time in the end
        OriginalFileName|contains: mavinject
    condition: selection 
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium

```
