---
title: "F-Secure C3 Load by Rundll32"
aliases:
  - "/rule/b18c9d4c-fac9-4708-bd06-dd5bfacf200f"
ruleid: b18c9d4c-fac9-4708-bd06-dd5bfacf200f

tags:
  - attack.defense_evasion
  - attack.t1218.011



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

F-Secure C3 produces DLLs with a default exported StartNodeRelay function.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/FSecureLABS/C3/blob/master/Src/NodeRelayDll/NodeRelayDll.cpp#L12


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_c3_load_by_rundll32.yml))
```yaml
title: F-Secure C3 Load by Rundll32
status: test
id: b18c9d4c-fac9-4708-bd06-dd5bfacf200f
author: Alfie Champion (ajpc500)
date: 2021/06/02
description: F-Secure C3 produces DLLs with a default exported StartNodeRelay function.
references:
    - https://github.com/FSecureLABS/C3/blob/master/Src/NodeRelayDll/NodeRelayDll.cpp#L12
tags:
    - attack.defense_evasion
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'rundll32.exe'
            - '.dll'
            - 'StartNodeRelay'
    condition: selection
falsepositives:
    - Unknown
level: critical

```
