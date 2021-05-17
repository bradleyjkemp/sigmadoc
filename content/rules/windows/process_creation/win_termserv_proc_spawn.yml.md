---
title: "Terminal Service Process Spawn"
aliases:
  - "/rule/1012f107-b8f1-4271-af30-5aed2de89b39"

tags:
  - attack.initial_access
  - attack.t1190
  - attack.lateral_movement
  - attack.t1210
  - car.2013-07-002



status: experimental



level: high



date: Wed, 22 May 2019 10:38:27 +0200


---

Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)

<!--more-->


## Known false-positives

* Unknown



## References

* https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708/


## Raw rule
```yaml
title: Terminal Service Process Spawn
id: 1012f107-b8f1-4271-af30-5aed2de89b39
status: experimental
description: Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)
references:
    - https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708/
author: Florian Roth
date: 2019/05/22
modified: 2020/08/29
tags:
    - attack.initial_access 
    - attack.t1190
    - attack.lateral_movement
    - attack.t1210
    - car.2013-07-002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentCommandLine: '*\svchost.exe*termsvcs'
    filter:
        Image: '*\rdpclip.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
