---
title: "Pass the Hash Activity"
aliases:
  - "/rule/f8d98d6c-7a07-4d74-b064-dd4a3c244528"
ruleid: f8d98d6c-7a07-4d74-b064-dd4a3c244528

tags:
  - attack.lateral_movement
  - car.2016-04-004
  - attack.t1550.002



status: test





date: Wed, 8 Mar 2017 18:04:31 +0100


---

Detects the attack technique pass the hash which is used to move laterally inside the network

<!--more-->


## Known false-positives

* Administrator activity
* Penetration tests



## References

* https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_pass_the_hash.yml))
```yaml
title: Pass the Hash Activity
id: f8d98d6c-7a07-4d74-b064-dd4a3c244528
status: test
description: Detects the attack technique pass the hash which is used to move laterally inside the network
author: Ilias el Matani (rule), The Information Assurance Directorate at the NSA (method)
references:
  - https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events
date: 2017/03/08
modified: 2021/11/27
logsource:
  product: windows
  service: security
  definition: The successful use of PtH for lateral movement between workstations would trigger event ID 4624, a failed logon attempt would trigger an event ID 4625
detection:
  selection:
    EventID:
      - 4624
      - 4625
    LogonType: '3'
    LogonProcessName: 'NtLmSsp'
    WorkstationName: '%Workstations%'
    ComputerName: '%Workstations%'
  filter:
    TargetUserName: 'ANONYMOUS LOGON'
  condition: selection and not filter
falsepositives:
  - Administrator activity
  - Penetration tests
level: medium
tags:
  - attack.lateral_movement
  - car.2016-04-004
  - attack.t1550.002

```
