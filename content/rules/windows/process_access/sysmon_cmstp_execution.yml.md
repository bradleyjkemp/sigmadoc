---
title: "CMSTP Execution"
aliases:
  - "/rule/9d26fede-b526-4413-b069-6e24b6d07167"

tags:
  - attack.defense_evasion
  - attack.t1218.003
  - attack.t1191
  - attack.execution
  - attack.t1559.001
  - attack.t1175
  - attack.g0069
  - attack.g0080
  - car.2019-04-001



date: Mon, 16 Jul 2018 02:53:41 +0300


---

Detects various indicators of Microsoft Connection Manager Profile Installer execution

<!--more-->


## Known false-positives

* Legitimate CMSTP use (unlikely in modern enterprise environments)



## References

* https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/


## Raw rule
```yaml
action: global
title: CMSTP Execution
id: 9d26fede-b526-4413-b069-6e24b6d07167
status: stable
description: Detects various indicators of Microsoft Connection Manager Profile Installer execution
tags:
    - attack.defense_evasion
    - attack.t1218.003
    - attack.t1191  # an old one
    - attack.execution
    - attack.t1559.001
    - attack.t1175  # an old one
    - attack.g0069
    - attack.g0080
    - car.2019-04-001
author: Nik Seetharaman
date: 2018/07/16
modified: 2020/08/24
references:
    - https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
fields:
    - CommandLine
    - ParentCommandLine
    - Details
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high
---
logsource:
    product: windows
    category: registry_event
detection:
    # Registry Object Add
    selection2:
        TargetObject: '*\cmmgr32.exe*'
        EventType: 'CreateKey'
    # Registry Object Value Set
    selection3:
        TargetObject: '*\cmmgr32.exe*'
    # Process Access Call Trace
    selection4:
        CallTrace: '*cmlua.dll*'
    condition: 1 of them
---
logsource:
    category: process_creation
    product: windows
detection:
    # CMSTP Spawning Child Process
    selection1:
        ParentImage: '*\cmstp.exe'
    condition: 1 of them

```
