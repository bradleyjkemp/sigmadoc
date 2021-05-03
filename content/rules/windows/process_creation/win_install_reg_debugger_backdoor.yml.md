---
title: "Suspicious Debugger Registration Cmdline"
aliases:
  - "/rule/ae215552-081e-44c7-805f-be16f975c8a2"

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1546.008
  - attack.t1015



date: Fri, 6 Sep 2019 10:28:09 +0200


---

Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).

<!--more-->


## Known false-positives

* Penetration Tests



## References

* https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/


## Raw rule
```yaml
title: Suspicious Debugger Registration Cmdline
id: ae215552-081e-44c7-805f-be16f975c8a2
status: experimental
description: Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).
references:
    - https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1546.008
    - attack.t1015  # an old one
author: Florian Roth
date: 2019/09/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\CurrentVersion\Image File Execution Options\sethc.exe*'
            - '*\CurrentVersion\Image File Execution Options\utilman.exe*'
            - '*\CurrentVersion\Image File Execution Options\osk.exe*'
            - '*\CurrentVersion\Image File Execution Options\magnify.exe*'
            - '*\CurrentVersion\Image File Execution Options\narrator.exe*'
            - '*\CurrentVersion\Image File Execution Options\displayswitch.exe*'
            - '*\CurrentVersion\Image File Execution Options\atbroker.exe*'
    condition: selection
falsepositives:
    - Penetration Tests
level: high


```
