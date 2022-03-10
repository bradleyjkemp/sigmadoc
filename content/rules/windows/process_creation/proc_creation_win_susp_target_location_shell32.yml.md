---
title: "Shell32 DLL Execution in Suspicious Directory"
aliases:
  - "/rule/32b96012-7892-429e-b26c-ac2bf46066ff"


tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1218.011



status: experimental





date: Wed, 24 Nov 2021 10:56:58 +0100


---

Detects shell32.dll executing a DLL in a suspicious directory

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.group-ib.com/resources/threat-research/red-curl-2.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_target_location_shell32.yml))
```yaml
title: Shell32 DLL Execution in Suspicious Directory
id: 32b96012-7892-429e-b26c-ac2bf46066ff
description: Detects shell32.dll executing a DLL in a suspicious directory
status: experimental
references:
    - https://www.group-ib.com/resources/threat-research/red-curl-2.html
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218.011
author: Christian Burkard
date: 2021/11/24
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains|all:
            - 'shell32.dll'
            - 'Control_RunDLL'
        CommandLine|contains:
            - '%AppData%'
            - '%LocalAppData%'
            - '%Temp%'
            - '\AppData\'
            - '\Temp\'
            - '\Users\Public\'
    condition: selection
falsepositives:
    - Unknown
level: high

```
