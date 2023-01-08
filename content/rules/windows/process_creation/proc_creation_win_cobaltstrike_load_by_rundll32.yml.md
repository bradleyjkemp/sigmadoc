---
title: "CobaltStrike Load by Rundll32"
aliases:
  - "/rule/ae9c6a7c-9521-42a6-915e-5aaa8689d529"
ruleid: ae9c6a7c-9521-42a6-915e-5aaa8689d529

tags:
  - attack.defense_evasion
  - attack.t1218.011



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Rundll32 can be use by Cobalt Strike with StartW function to load DLLs from the command line.

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.cobaltstrike.com/help-windows-executable
* https://redcanary.com/threat-detection-report/
* https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_cobaltstrike_load_by_rundll32.yml))
```yaml
title: CobaltStrike Load by Rundll32
status: experimental
id: ae9c6a7c-9521-42a6-915e-5aaa8689d529
author: Wojciech Lesicki
date: 2021/06/01
modified: 2022/03/04
description: Rundll32 can be use by Cobalt Strike with StartW function to load DLLs from the command line.
references:
    - https://www.cobaltstrike.com/help-windows-executable
    - https://redcanary.com/threat-detection-report/
    - https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/
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
        CommandLine|endswith: 
            - ' StartW'
            - ',StartW'
    condition: selection
falsepositives:
    - Unknown
level: critical

```
