---
title: "Suspicious Reconnaissance Activity"
aliases:
  - "/rule/d95de845-b83c-4a9a-8a6a-4fc802ebf6c0"

tags:
  - attack.discovery
  - attack.t1087.001
  - attack.t1087.002
  - attack.t1087



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious command line activity on Windows systems

<!--more-->


## Known false-positives

* Inventory tool runs
* Penetration tests
* Administrative activity




## Raw rule
```yaml
title: Suspicious Reconnaissance Activity
id: d95de845-b83c-4a9a-8a6a-4fc802ebf6c0
status: experimental
description: Detects suspicious command line activity on Windows systems
author: Florian Roth
date: 2019/01/16
modified: 2020/08/28
tags:
    - attack.discovery
    - attack.t1087.001
    - attack.t1087.002
    - attack.t1087      # an old one 
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - net group "domain admins" /domain
            - net localgroup administrators
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Inventory tool runs
    - Penetration tests
    - Administrative activity
analysis:
    recommendation: Check if the user that executed the commands is suspicious (e.g. service accounts, LOCAL_SYSTEM)
level: medium

```
