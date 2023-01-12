---
title: "WMI Backdoor Exchange Transport Agent"
aliases:
  - "/rule/797011dc-44f4-4e6f-9f10-a8ceefbe566b"
ruleid: 797011dc-44f4-4e6f-9f10-a8ceefbe566b

tags:
  - attack.persistence
  - attack.t1546.003



status: test





date: Fri, 11 Oct 2019 12:12:30 +0200


---

Detects a WMI backdoor in Exchange Transport Agents via WMI event filters

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/cglyer/status/1182389676876980224
* https://twitter.com/cglyer/status/1182391019633029120


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_wmi_backdoor_exchange_transport_agent.yml))
```yaml
title: WMI Backdoor Exchange Transport Agent
id: 797011dc-44f4-4e6f-9f10-a8ceefbe566b
status: test
description: Detects a WMI backdoor in Exchange Transport Agents via WMI event filters
author: Florian Roth
references:
  - https://twitter.com/cglyer/status/1182389676876980224
  - https://twitter.com/cglyer/status/1182391019633029120
date: 2019/10/11
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\EdgeTransport.exe'
  condition: selection
falsepositives:
  - Unknown
level: critical
tags:
  - attack.persistence
  - attack.t1546.003

```