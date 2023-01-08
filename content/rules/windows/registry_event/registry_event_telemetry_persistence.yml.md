---
title: "Registry Persistence Mechanism via Windows Telemetry"
aliases:
  - "/rule/73a883d0-0348-4be4-a8d8-51031c2564f8"
ruleid: 73a883d0-0348-4be4-a8d8-51031c2564f8

tags:
  - attack.persistence
  - attack.t1053.005



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects persistence method using windows telemetry

<!--more-->


## Known false-positives

* unknown



## References

* https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_telemetry_persistence.yml))
```yaml
title: Registry Persistence Mechanism via Windows Telemetry
id: 73a883d0-0348-4be4-a8d8-51031c2564f8
status: test
description: Detects persistence method using windows telemetry
author: Lednyov Alexey, oscd.community
references:
  - https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/
date: 2020/10/16
modified: 2022/01/13
logsource:
  category: registry_event
  product: windows
  definition: 'Requirements: Sysmon config that monitors \SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController subkey of the HKLU hives'
detection:
  selection:
    EventType: SetValue 
    TargetObject|contains|all:
      - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\'
      - '\Command'
    Details|contains: '.exe'
  filter:
    Details|contains:
      - '\system32\CompatTelRunner.exe'
      - '\system32\DeviceCensus.exe'
  condition: selection and not filter
falsepositives:
  - unknown
level: critical
tags:
  - attack.persistence
  - attack.t1053.005

```
