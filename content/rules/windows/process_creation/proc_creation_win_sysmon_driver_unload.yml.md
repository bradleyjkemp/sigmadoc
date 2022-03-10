---
title: "Sysmon Driver Unload"
aliases:
  - "/rule/4d7cda18-1b12-4e52-b45c-d28653210df8"


tags:
  - attack.defense_evasion
  - attack.t1070
  - attack.t1562
  - attack.t1562.002



status: experimental





date: Wed, 23 Oct 2019 14:27:52 +0300


---

Detect possible Sysmon driver unload

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_sysmon_driver_unload.yml))
```yaml
title: Sysmon Driver Unload
id: 4d7cda18-1b12-4e52-b45c-d28653210df8
status: experimental
author: Kirill Kiryanov, oscd.community
description: Detect possible Sysmon driver unload
date: 2019/10/23
modified: 2021/09/27
references:
    - https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon
logsource:
    product: windows
    category: process_creation
tags:
    - attack.defense_evasion
    - attack.t1070
    - attack.t1562
    - attack.t1562.002
detection:
    selection:
        Image|endswith: '\fltmc.exe'
        CommandLine|contains|all:
            - 'unload'
            - 'sys'
    condition: selection
falsepositives: 
    - Unknown
level: high
fields:
    - CommandLine
    - Details

```