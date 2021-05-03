---
title: "Suspicious PROCEXP152.sys File Created In TMP"
aliases:
  - "/rule/3da70954-0f2c-4103-adff-b7440368f50e"

tags:
  - attack.t1089
  - attack.t1562.001
  - attack.defense_evasion



date: Wed, 8 Apr 2020 17:57:47 +0200


---

Detects the creation of the PROCEXP152.sys file in the application-data local temporary folder. This driver is used by Sysinternals Process Explorer but also by KDU (https://github.com/hfiref0x/KDU) or Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU.

<!--more-->


## Known false-positives

* Other legimate tools using this driver and filename (like Sysinternals). Note - Clever attackers may easily bypass this detection by just renaming the driver filename. Therefore just Medium-level and don't rely on it.



## References

* https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/


## Raw rule
```yaml
title: Suspicious PROCEXP152.sys File Created In TMP
id: 3da70954-0f2c-4103-adff-b7440368f50e
description: Detects the creation of the PROCEXP152.sys file in the application-data local temporary folder. This driver is used by Sysinternals Process Explorer but also by KDU (https://github.com/hfiref0x/KDU) or Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU.
status: experimental
date: 2019/04/08
author: xknow (@xknow_infosec), xorxes (@xor_xes)
references:
    - https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/
tags:
    - attack.t1089          # an old one
    - attack.t1562.001
    - attack.defense_evasion
logsource:
    product: windows
    category: file_event
detection:
    selection_1:
        TargetFilename: '*\AppData\Local\Temp\\*\PROCEXP152.sys'
    selection_2:
        Image|contains:
            - '*\procexp64.exe'
            - '*\procexp.exe'
            - '*\procmon64.exe'
            - '*\procmon.exe'
    condition: selection_1 and not selection_2
falsepositives:
    - Other legimate tools using this driver and filename (like Sysinternals). Note - Clever attackers may easily bypass this detection by just renaming the driver filename. Therefore just Medium-level and don't rely on it.
level: medium

```