---
title: "Hiding Files with Attrib.exe"
aliases:
  - "/rule/4281cb20-2994-4580-aa63-c8b86d019934"

tags:
  - attack.defense_evasion
  - attack.t1564.001
  - attack.t1158



status: experimental



level: low



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects usage of attrib.exe to hide files from users.

<!--more-->


## Known false-positives

* igfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)
* msiexec.exe hiding desktop.ini




## Raw rule
```yaml
title: Hiding Files with Attrib.exe
id: 4281cb20-2994-4580-aa63-c8b86d019934
status: experimental
description: Detects usage of attrib.exe to hide files from users.
author: Sami Ruohonen
date: 2019/01/16
modified: 2020/08/27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\attrib.exe'
        CommandLine: '* +h *'
    ini:
        CommandLine: '*\desktop.ini *'
    intel:
        ParentImage: '*\cmd.exe'
        CommandLine: +R +H +S +A \\*.cui
        ParentCommandLine: C:\WINDOWS\system32\\*.bat
    condition: selection and not (ini or intel)
fields:
    - CommandLine
    - ParentCommandLine
    - User
tags:
    - attack.defense_evasion
    - attack.t1564.001
    - attack.t1158  # an old one
falsepositives:
    - igfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)
    - msiexec.exe hiding desktop.ini
level: low

```
