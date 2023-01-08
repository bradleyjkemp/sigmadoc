---
title: "Suspicious Debugger Registration Cmdline"
aliases:
  - "/rule/ae215552-081e-44c7-805f-be16f975c8a2"
ruleid: ae215552-081e-44c7-805f-be16f975c8a2

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1546.008



status: test





date: Fri, 6 Sep 2019 10:28:09 +0200


---

Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).

<!--more-->


## Known false-positives

* Penetration Tests



## References

* https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_install_reg_debugger_backdoor.yml))
```yaml
title: Suspicious Debugger Registration Cmdline
id: ae215552-081e-44c7-805f-be16f975c8a2
status: test
description: Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).
author: Florian Roth, oscd.community, Jonhnathan Ribeiro
references:
  - https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
date: 2019/09/06
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - '\CurrentVersion\Image File Execution Options\'
    CommandLine|contains:
      - 'sethc.exe'
      - 'utilman.exe'
      - 'osk.exe'
      - 'magnify.exe'
      - 'narrator.exe'
      - 'displayswitch.exe'
      - 'atbroker.exe'
  condition: selection
falsepositives:
  - Penetration Tests
level: high
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1546.008

```
