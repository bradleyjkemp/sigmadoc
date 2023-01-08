---
title: "Abusing Windows Telemetry For Persistence"
aliases:
  - "/rule/4e8d5fd3-c959-441f-a941-f73d0cdcdca5"
ruleid: 4e8d5fd3-c959-441f-a941-f73d0cdcdca5

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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_abusing_windows_telemetry_for_persistence.yml))
```yaml
title: Abusing Windows Telemetry For Persistence
id: 4e8d5fd3-c959-441f-a941-f73d0cdcdca5
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
modified: 2022/01/13
fields:
    - EventID
    - CommandLine
    - TargetObject
    - Details
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        EventType: SetValue
        TargetObject|contains: 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\'
        Details|endswith: 
            - .sh
            - .exe
            - .dll
            - .bin
            - .bat
            - .cmd
            - .js
            - .ps
            - .vb
            - .jar
            - .hta
            - .msi
            - .vbs
    condition: selection
falsepositives:
    - none
level: high
```
