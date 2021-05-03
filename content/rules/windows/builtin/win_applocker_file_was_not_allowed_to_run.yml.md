---
title: "File Was Not Allowed To Run"
aliases:
  - "/rule/401e5d00-b944-11ea-8f9a-00163ecd60ae"

tags:
  - attack.execution
  - attack.t1086
  - attack.t1064
  - attack.t1204
  - attack.t1035
  - attack.t1204.002
  - attack.t1059.001
  - attack.t1059.003
  - attack.t1059.005
  - attack.t1059.006
  - attack.t1059.007



date: Mon, 13 Jul 2020 20:51:48 +0000


---

Detect run not allowed files. Applocker is a very useful tool, especially on servers where unprivileged users have access. For example terminal servers. You need configure applocker and log collect to receive these events.

<!--more-->


## Known false-positives

* need tuning applocker or add exceptions in SIEM



## References

* https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker
* https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/using-event-viewer-with-applocker
* https://nxlog.co/documentation/nxlog-user-guide/applocker.html


## Raw rule
```yaml
title: File Was Not Allowed To Run 
id: 401e5d00-b944-11ea-8f9a-00163ecd60ae
description: Detect run not allowed files. Applocker is a very useful tool, especially on servers where unprivileged users have access. For example terminal servers. You need configure applocker and log collect to receive these events.
status: experimental
tags:
    - attack.execution
    - attack.t1086          # an old one
    - attack.t1064          # an old one
    - attack.t1204          # an old one
    - attack.t1035          # an old one
    - attack.t1204.002
    - attack.t1059.001
    - attack.t1059.003
    - attack.t1059.005
    - attack.t1059.006
    - attack.t1059.007
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/using-event-viewer-with-applocker
    - https://nxlog.co/documentation/nxlog-user-guide/applocker.html
author: Pushkarev Dmitry
date: 2020/06/28
modified: 2020/08/23
logsource:
    product: windows
    service: applocker
detection:
    selection:
        EventID:
          - 8004
          - 8007
    condition: selection
fields:
    - PolicyName
    - RuleId
    - RuleName
    - TargetUser
    - TargetProcessId
    - FilePath
    - FileHash
    - Fqbn
falsepositives:
    - need tuning applocker or add exceptions in SIEM
level: medium

```