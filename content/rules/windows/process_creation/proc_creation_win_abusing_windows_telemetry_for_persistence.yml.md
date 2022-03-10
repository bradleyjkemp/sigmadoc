---
title: "Abusing Windows Telemetry For Persistence"
aliases:
  - "/rule/f548a603-c9f2-4c89-b511-b089f7e94549"


tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.t1112
  - attack.t1053



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Windows telemetry makes use of the binary CompatTelRunner.exe to run a variety of commands and perform the actual telemetry collections. This binary was created to be easily extensible, and to that end, it relies on the registry to instruct on which commands to run. The problem is, it will run any arbitrary command without restriction of location or type.

<!--more-->


## Known false-positives

* none



## References

* https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_abusing_windows_telemetry_for_persistence.yml))
```yaml
title: Abusing Windows Telemetry For Persistence
id: f548a603-c9f2-4c89-b511-b089f7e94549
status: experimental
description: Windows telemetry makes use of the binary CompatTelRunner.exe to run a variety of commands and perform the actual telemetry collections. This binary was created to be easily extensible, and to that end, it relies on the registry to instruct on which commands to run. The problem is, it will run any arbitrary command without restriction of location or type.
references:
    - https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1112
    - attack.t1053
author: Sreeman
date: 2020/09/29
modified: 2022/02/21
fields:
    - EventID
    - CommandLine
    - TargetObject
    - Details
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all: 
            - 'schtasks'
            - '\Application Experience\Microsoft Compatibility Appraiser'
    condition: selection
falsepositives:
    - none
level: high

```
