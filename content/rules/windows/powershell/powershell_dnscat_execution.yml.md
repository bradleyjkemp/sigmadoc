---
title: "Dnscat Execution"
aliases:
  - "/rule/a6d67db4-6220-436d-8afc-f3842fe05d43"

tags:
  - attack.exfiltration
  - attack.t1048
  - attack.execution
  - attack.t1059.001
  - attack.t1086



status: experimental



level: critical



date: Fri, 25 Oct 2019 04:30:55 +0200


---

Dnscat exfiltration tool execution

<!--more-->


## Known false-positives

* Legitimate usage of PowerShell Dnscat2 — DNS Exfiltration tool (unlikely)




## Raw rule
```yaml
title: Dnscat Execution
id: a6d67db4-6220-436d-8afc-f3842fe05d43
description: Dnscat exfiltration tool execution
status: experimental
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2020/08/24
tags:
    - attack.exfiltration
    - attack.t1048
    - attack.execution
    - attack.t1059.001
    - attack.t1086  # an old one
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains: "Start-Dnscat2"
    condition: selection
falsepositives:
    - Legitimate usage of PowerShell Dnscat2 — DNS Exfiltration tool (unlikely)
level: critical

```
