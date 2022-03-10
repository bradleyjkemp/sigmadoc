---
title: "Suspicious VBScript UN2452 Pattern"
aliases:
  - "/rule/20c3f09d-c53d-4e85-8b74-6aa50e2f1b61"


tags:
  - attack.persistence
  - attack.t1547.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects suspicious inline VBScript keywords as used by UNC2452

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_vbscript_unc2452.yml))
```yaml
title: Suspicious VBScript UN2452 Pattern
id: 20c3f09d-c53d-4e85-8b74-6aa50e2f1b61
description: Detects suspicious inline VBScript keywords as used by UNC2452
status: experimental
references:
    - https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/
author: Florian Roth
date: 2021/03/05
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - 'Execute'
            - 'CreateObject'
            - 'RegRead'
            - 'window.close'
            - '\Microsoft\Windows\CurrentVersion'
    filter:
        CommandLine|contains:
            - '\Software\Microsoft\Windows\CurrentVersion\Run'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
tags:
    - attack.persistence
    - attack.t1547.001
```
