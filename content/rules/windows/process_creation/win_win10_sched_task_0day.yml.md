---
title: "Windows 10 Scheduled Task SandboxEscaper 0-day"
aliases:
  - "/rule/931b6802-d6a6-4267-9ffa-526f57f22aaf"

tags:
  - attack.privilege_escalation
  - attack.t1053.005
  - attack.t1053
  - car.2013-08-001



status: experimental



level: high



date: Wed, 22 May 2019 12:28:42 +0200


---

Detects Task Scheduler .job import arbitrary DACL write\par

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe


## Raw rule
```yaml
title: Windows 10 Scheduled Task SandboxEscaper 0-day
id: 931b6802-d6a6-4267-9ffa-526f57f22aaf
status: experimental
description: Detects Task Scheduler .job import arbitrary DACL write\par
references:
    - https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe
author: Olaf Hartong
date: 2019/05/22
modified: 2020/08/29
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine: '*/change*/TN*/RU*/RP*'
    condition: selection
falsepositives:
    - Unknown
tags:
    - attack.privilege_escalation
    - attack.t1053.005
    - attack.t1053      # an old one
    - car.2013-08-001
level: high

```
