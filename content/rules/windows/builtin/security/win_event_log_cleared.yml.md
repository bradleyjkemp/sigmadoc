---
title: "Security Event Log Cleared"
aliases:
  - "/rule/a122ac13-daf8-4175-83a2-72c387be339d"
ruleid: a122ac13-daf8-4175-83a2-72c387be339d

tags:
  - attack.t1070.001



status: experimental





date: Sun, 15 Aug 2021 16:00:14 +0200


---

Checks for event id 1102 which indicates the security event log was cleared.

<!--more-->


## Known false-positives

* Legitimate administrative activity



## References

* https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/SecurityEventLogCleared.yaml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_event_log_cleared.yml))
```yaml
title: Security Event Log Cleared
id: a122ac13-daf8-4175-83a2-72c387be339d
status: experimental
description: Checks for event id 1102 which indicates the security event log was cleared.
references: 
  - https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/SecurityEventLogCleared.yaml
date: 2021/08/15
modified: 2021/10/13
author: Saw Winn Naung
level: medium
logsource:                     
    service: security  
    product: windows 
tags:
    - attack.t1070.001
detection:
    selection:
        EventID: 1102
        Provider_Name: Microsoft-Windows-Eventlog
    condition: selection
fields:
    - SubjectLogonId
    - SubjectUserName
    - SubjectUserSid
    - SubjectDomainName
falsepositives:
    - Legitimate administrative activity

```
