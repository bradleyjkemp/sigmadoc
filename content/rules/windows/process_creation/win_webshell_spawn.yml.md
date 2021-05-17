---
title: "Shells Spawned by Web Servers"
aliases:
  - "/rule/8202070f-edeb-4d31-a010-a26c72ac5600"

tags:
  - attack.persistence
  - attack.t1505.003
  - attack.privilege_escalation
  - attack.t1100



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack

<!--more-->


## Known false-positives

* Particular web applications may spawn a shell process legitimately




## Raw rule
```yaml
title: Shells Spawned by Web Servers
id: 8202070f-edeb-4d31-a010-a26c72ac5600
status: experimental
description: Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack
author: Thomas Patzke
date: 2019/01/16
modified: 2020/03/25
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\w3wp.exe'
            - '*\httpd.exe'
            - '*\nginx.exe'
            - '*\php-cgi.exe'
            - '*\tomcat.exe'
        Image:
            - '*\cmd.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\powershell.exe'
            - '*\bitsadmin.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.privilege_escalation       # an old one
    - attack.t1100      # an old one
falsepositives:
    - Particular web applications may spawn a shell process legitimately
level: high

```
