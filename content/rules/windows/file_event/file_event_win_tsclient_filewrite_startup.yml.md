---
title: "Hijack Legit RDP Session to Move Laterally"
aliases:
  - "/rule/52753ea4-b3a0-4365-910d-36cff487b789"


tags:
  - attack.command_and_control
  - attack.t1219



status: test





date: Wed, 3 Apr 2019 13:19:59 +0200


---

Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder

<!--more-->


## Known false-positives

* unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_tsclient_filewrite_startup.yml))
```yaml
title: Hijack Legit RDP Session to Move Laterally
id: 52753ea4-b3a0-4365-910d-36cff487b789
status: test
description: Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder
author: Samir Bousseaden
date: 2019/02/21
modified: 2021/11/27
logsource:
  product: windows
  category: file_event
detection:
  selection:
    Image|endswith: '\mstsc.exe'
    TargetFilename|contains: '\Microsoft\Windows\Start Menu\Programs\Startup\'
  condition: selection
falsepositives:
  - unknown
level: high
tags:
  - attack.command_and_control
  - attack.t1219

```
