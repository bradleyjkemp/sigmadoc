---
title: "Suspicious Add Scheduled Task From User AppData Temp"
aliases:
  - "/rule/43f487f0-755f-4c2a-bce7-d6d2eec2fcf8"


tags:
  - attack.execution
  - attack.t1053.005



status: experimental





date: Wed, 3 Nov 2021 15:14:34 +0100


---

schtasks.exe create task from user AppData\Local\Temp

<!--more-->


## Known false-positives

* unknown



## References

* malware analyse https://www.joesandbox.com/analysis/514608/0/html#324415FF7D8324231381BAD48A052F85DF04


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_schtasks_user_temp.yml))
```yaml
title: Suspicious Add Scheduled Task From User AppData Temp 
id: 43f487f0-755f-4c2a-bce7-d6d2eec2fcf8
description: schtasks.exe create task from user AppData\Local\Temp
status: experimental
references:
    - malware analyse https://www.joesandbox.com/analysis/514608/0/html#324415FF7D8324231381BAD48A052F85DF04
tags:
    - attack.execution
    - attack.t1053.005 
author: frack113
date: 2021/11/03
modified: 2022/02/09
logsource:
    product: windows
    category: process_creation
detection:
    schtasks:
        Image|endswith: 'schtasks.exe'
    option:
        CommandLine|contains|all:
            - '/Create '
            - '\AppData\Local\Temp'
    filter_klite_codec:
        CommandLine|contains|all:
            - '/Create /TN "klcp_update" /XML '
            - '\klcp_update_task.xml'
    condition: schtasks and option and not 1 of filter_*
falsepositives:
    - unknown
level: high

```
