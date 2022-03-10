---
title: "Renamed PAExec"
aliases:
  - "/rule/c4e49831-1496-40cf-8ce1-b53f942b02f9"


tags:
  - attack.defense_evasion
  - attack.t1202



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects suspicious renamed PAExec execution as often used by attackers

<!--more-->


## Known false-positives

* Weird admins that rename their tools
* Software companies that bundle PAExec with their software and rename it, so that it is less embarrassing



## References

* https://www.poweradmin.com/paexec/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_renamed_paexec.yml))
```yaml
title: Renamed PAExec
id: c4e49831-1496-40cf-8ce1-b53f942b02f9
status: experimental
description: Detects suspicious renamed PAExec execution as often used by attackers
references:
    - https://www.poweradmin.com/paexec/
author: Florian Roth
date: 2021/05/22
modified: 2021/07/06
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Description: 'PAExec Application'
    selection2:
        OriginalFileName: 'PAExec.exe'
    filter:
        Image|endswith: 
            - '\PAexec.exe'
            - '\paexec.exe'
    condition: ( selection1 or selection2 ) and not filter
falsepositives:
    - Weird admins that rename their tools
    - Software companies that bundle PAExec with their software and rename it, so that it is less embarrassing 
level: high
tags:
    - attack.defense_evasion 
    - attack.t1202 
```
