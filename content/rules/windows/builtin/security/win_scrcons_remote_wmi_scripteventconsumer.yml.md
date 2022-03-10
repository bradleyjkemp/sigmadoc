---
title: "Remote WMI ActiveScriptEventConsumers"
aliases:
  - "/rule/9599c180-e3a8-4743-8f92-7fb96d3be648"


tags:
  - attack.lateral_movement
  - attack.privilege_escalation
  - attack.persistence
  - attack.t1546.003



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detect potential adversaries leveraging WMI ActiveScriptEventConsumers remotely to move laterally in a network

<!--more-->


## Known false-positives

* SCCM



## References

* https://threathunterplaybook.com/notebooks/windows/08_lateral_movement/WIN-200902020333.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_scrcons_remote_wmi_scripteventconsumer.yml))
```yaml
title: Remote WMI ActiveScriptEventConsumers
id: 9599c180-e3a8-4743-8f92-7fb96d3be648
status: test
description: Detect potential adversaries leveraging WMI ActiveScriptEventConsumers remotely to move laterally in a network
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
references:
  - https://threathunterplaybook.com/notebooks/windows/08_lateral_movement/WIN-200902020333.html
date: 2020/09/02
modified: 2021/11/27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    ProcessName|endswith: 'scrcons.exe'
  filter:
    TargetLogonId: '0x3e7'
  condition: selection and not filter
falsepositives:
  - SCCM
level: high
tags:
  - attack.lateral_movement
  - attack.privilege_escalation
  - attack.persistence
  - attack.t1546.003

```