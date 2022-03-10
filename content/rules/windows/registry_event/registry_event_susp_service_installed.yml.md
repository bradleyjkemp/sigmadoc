---
title: "Suspicious Service Installed"
aliases:
  - "/rule/f2485272-a156-4773-82d7-1d178bc4905b"


tags:
  - attack.t1562.001
  - attack.defense_evasion



status: test





date: Wed, 8 Apr 2020 17:57:47 +0200


---

Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders. Both services are used in the tool Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU (https://github.com/hfiref0x/KDU)

<!--more-->


## Known false-positives

* Other legimate tools using this service names and drivers. Note - clever attackers may easily bypass this detection by just renaming the services. Therefore just Medium-level and don't rely on it.



## References

* https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_susp_service_installed.yml))
```yaml
title: Suspicious Service Installed
id: f2485272-a156-4773-82d7-1d178bc4905b
status: test
description: Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders. Both services are used in the tool Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU (https://github.com/hfiref0x/KDU)
author: xknow (@xknow_infosec), xorxes (@xor_xes)
references:
  - https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/
date: 2019/04/08
modified: 2022/01/13
logsource:
  category: registry_event
  product: windows
detection:
  selection_1:
    EventType: SetValue
    TargetObject:
      - 'HKLM\System\CurrentControlSet\Services\NalDrv\ImagePath'
      - 'HKLM\System\CurrentControlSet\Services\PROCEXP152\ImagePath'
  selection_2:
    Image|endswith:
      - '\procexp64.exe'
      - '\procexp.exe'
      - '\procmon64.exe'
      - '\procmon.exe'
  selection_3:
    Details|contains:
      - '\WINDOWS\system32\Drivers\PROCEXP152.SYS'
  condition: selection_1 and not selection_2 and not selection_3
falsepositives:
  - Other legimate tools using this service names and drivers. Note - clever attackers may easily bypass this detection by just renaming the services. Therefore just Medium-level and don't rely on it.
level: medium
tags:
  - attack.t1562.001
  - attack.defense_evasion

```
