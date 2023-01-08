---
title: "Suspicious Rundll32 Invoking Inline VBScript"
aliases:
  - "/rule/1cc50f3f-1fc8-4acf-b2e9-6f172e1fdebd"
ruleid: 1cc50f3f-1fc8-4acf-b2e9-6f172e1fdebd

tags:
  - attack.defense_evasion
  - attack.t1055



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects suspicious process related to rundll32 based on command line that invokes inline VBScript as seen being used by UNC2452

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_rundll32_inline_vbs.yml))
```yaml
title: Suspicious Rundll32 Invoking Inline VBScript
id: 1cc50f3f-1fc8-4acf-b2e9-6f172e1fdebd
description: Detects suspicious process related to rundll32 based on command line that invokes inline VBScript as seen being used by UNC2452
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
            - 'rundll32.exe'
            - 'Execute'
            - 'RegRead'
            - 'window.close'
    condition: selection
falsepositives:
    - Unknown
level: high
tags:
    - attack.defense_evasion
    - attack.t1055
```
