---
title: "Remote Task Creation via ATSVC Named Pipe"
aliases:
  - "/rule/f6de6525-4509-495a-8a82-1f8b0ed73a00"
ruleid: f6de6525-4509-495a-8a82-1f8b0ed73a00

tags:
  - attack.lateral_movement
  - attack.persistence
  - car.2013-05-004
  - car.2015-04-001
  - attack.t1053.002



status: test





date: Wed, 3 Apr 2019 13:08:12 +0200


---

Detects remote task creation via at.exe or API interacting with ATSVC namedpipe

<!--more-->


## Known false-positives

* pentesting



## References

* https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_atsvc_task.yml))
```yaml
title: Remote Task Creation via ATSVC Named Pipe
id: f6de6525-4509-495a-8a82-1f8b0ed73a00
status: test
description: Detects remote task creation via at.exe or API interacting with ATSVC namedpipe
author: Samir Bousseaden
references:
  - https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html
date: 2019/04/03
modified: 2021/11/27
logsource:
  product: windows
  service: security
  definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
  selection:
    EventID: 5145
    ShareName: \\\*\IPC$
    RelativeTargetName: atsvc
    Accesses|contains: 'WriteData'
  condition: selection
falsepositives:
  - pentesting
level: medium
tags:
  - attack.lateral_movement
  - attack.persistence
  - car.2013-05-004
  - car.2015-04-001
  - attack.t1053.002

```
