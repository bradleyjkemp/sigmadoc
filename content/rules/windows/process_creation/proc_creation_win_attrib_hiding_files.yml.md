---
title: "Hiding Files with Attrib.exe"
aliases:
  - "/rule/4281cb20-2994-4580-aa63-c8b86d019934"
ruleid: 4281cb20-2994-4580-aa63-c8b86d019934

tags:
  - attack.defense_evasion
  - attack.t1564.001



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects usage of attrib.exe to hide files from users.

<!--more-->


## Known false-positives

* igfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)
* msiexec.exe hiding desktop.ini




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_attrib_hiding_files.yml))
```yaml
title: Hiding Files with Attrib.exe
id: 4281cb20-2994-4580-aa63-c8b86d019934
status: test
description: Detects usage of attrib.exe to hide files from users.
author: Sami Ruohonen
date: 2019/01/16
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\attrib.exe'
    CommandLine|contains: ' +h '
  ini:
    CommandLine|contains: '\desktop.ini '
  intel:
    ParentImage|endswith: '\cmd.exe'
    CommandLine: +R +H +S +A \\*.cui
    ParentCommandLine: C:\WINDOWS\system32\\*.bat
  condition: selection and not (ini or intel)
fields:
  - CommandLine
  - ParentCommandLine
  - User
falsepositives:
  - igfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)
  - msiexec.exe hiding desktop.ini
level: low
tags:
  - attack.defense_evasion
  - attack.t1564.001

```
