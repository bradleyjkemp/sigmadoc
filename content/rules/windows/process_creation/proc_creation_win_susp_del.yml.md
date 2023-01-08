---
title: "Suspicious Del in CommandLine"
aliases:
  - "/rule/204b17ae-4007-471b-917b-b917b315c5db"
ruleid: 204b17ae-4007-471b-917b-b917b315c5db

tags:
  - attack.defense_evasion
  - attack.t1070.004



status: experimental





date: Tue, 26 Oct 2021 13:17:56 +0200


---

suspicious command line to remove exe or dll

<!--more-->


## Known false-positives

* unknown



## References

* https://www.joesandbox.com/analysis/509330/0/html#1044F3BDBE3BB6F734E357235F4D5898582D


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_del.yml))
```yaml
title: Suspicious Del in CommandLine
id: 204b17ae-4007-471b-917b-b917b315c5db
status: experimental
description: suspicious command line to remove exe or dll
author: frack113
date: 2021/12/02
references:
    - https://www.joesandbox.com/analysis/509330/0/html#1044F3BDBE3BB6F734E357235F4D5898582D
tags:
    - attack.defense_evasion
    - attack.t1070.004 
logsource:
    category: process_creation
    product: windows
detection:
    susp_del_exe:
        CommandLine|contains|all:
            - 'del *.exe'
            - '/f '
            - '/q '
    susp_del_dll:
        CommandLine|contains|all:
            - 'del *.dll'
            - 'C:\ProgramData\'
    condition: susp_del_exe or susp_del_dll
#cmd.exe (PID: 1044 cmdline: 'C:\Windows\System32\cmd.exe' /c taskkill /im A8D4.exe /f & timeout /t 6 & del /f /q 'C:\Users\user~1\AppData\Local\Temp\A8D4.exe' & del C:\ProgramData\*.dll & exit 
falsepositives:
    - unknown
level: medium

```
