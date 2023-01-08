---
title: "Suspicious MsiExec Directory"
aliases:
  - "/rule/e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144"
ruleid: e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144

tags:
  - attack.defense_evasion
  - attack.t1036.005



status: test





date: Thu, 14 Nov 2019 09:51:55 +0100


---

Detects suspicious msiexec process starts in an uncommon directory

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/200_okay_/status/1194765831911215104


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_msiexec_cwd.yml))
```yaml
title: Suspicious MsiExec Directory
id: e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144
status: test
description: Detects suspicious msiexec process starts in an uncommon directory
author: Florian Roth
references:
  - https://twitter.com/200_okay_/status/1194765831911215104
date: 2019/11/14
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\msiexec.exe'
  filter:
    Image|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
      - 'C:\Windows\WinSxS\'
  condition: selection and not filter
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1036.005

```
