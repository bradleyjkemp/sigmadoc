---
title: "CMSTP Execution Registry Event"
aliases:
  - "/rule/b6d235fc-1d38-4b12-adbe-325f06728f37"


tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1218.003
  - attack.g0069
  - car.2019-04-001



status: stable





date: Mon, 16 Jul 2018 02:53:41 +0300


---

Detects various indicators of Microsoft Connection Manager Profile Installer execution

<!--more-->


## Known false-positives

* Legitimate CMSTP use (unlikely in modern enterprise environments)



## References

* https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_cmstp_execution_by_registry.yml))
```yaml
title: CMSTP Execution Registry Event
id: b6d235fc-1d38-4b12-adbe-325f06728f37
status: stable
description: Detects various indicators of Microsoft Connection Manager Profile Installer execution
author: Nik Seetharaman
date: 2018/07/16
modified: 2020/12/23
references:
    - https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
fields:
    - CommandLine
    - ParentCommandLine
    - Details
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains: '\cmmgr32.exe'
    condition: selection
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218.003
    - attack.g0069
    - car.2019-04-001
```
