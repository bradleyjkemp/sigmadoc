---
title: "Whoami Execution"
aliases:
  - "/rule/e28a5a99-da44-436d-b7a0-2afc20a5f413"

tags:
  - attack.discovery
  - attack.t1033
  - car.2016-03-001



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators

<!--more-->


## Known false-positives

* Admin activity
* Scripts and administrative tools used in the monitored environment



## References

* https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/
* https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/


## Raw rule
```yaml
title: Whoami Execution
id: e28a5a99-da44-436d-b7a0-2afc20a5f413
status: experimental
description: Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators
references:
    - https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/
    - https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/
author: Florian Roth
date: 2018/08/13
tags:
    - attack.discovery
    - attack.t1033
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\whoami.exe'
    selection2:
        OriginalFileName: 'whoami.exe'
    condition: selection or selection2
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment
level: high

```
