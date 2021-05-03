---
title: "PSExec and WMI Process Creations Block"
aliases:
  - "/rule/97b9ce1e-c5ab-11ea-87d0-0242ac130003"

tags:
  - attack.execution
  - attack.lateral_movement
  - attack.t1047
  - attack.t1035
  - attack.t1569.002



date: Tue, 14 Jul 2020 14:01:43 +0545


---

Detects blocking of process creations originating from PSExec and WMI commands

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction?WT.mc_id=twitter#block-process-creations-originating-from-psexec-and-wmi-commands
* https://twitter.com/duff22b/status/1280166329660497920


## Raw rule
```yaml
title: PSExec and WMI Process Creations Block
id: 97b9ce1e-c5ab-11ea-87d0-0242ac130003
description: Detects blocking of process creations originating from PSExec and WMI commands
status: experimental
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction?WT.mc_id=twitter#block-process-creations-originating-from-psexec-and-wmi-commands
    - https://twitter.com/duff22b/status/1280166329660497920
author: Bhabesh Raj
date: 2020/07/14
tags:
    - attack.execution
    - attack.lateral_movement
    - attack.t1047
    - attack.t1035 # an old one
    - attack.t1569.002
logsource:
    product: windows_defender
    definition: 'Requirements:Enabled Block process creations originating from PSExec and WMI commands from Attack Surface Reduction (GUID: d1e49aac-8f56-4280-b9ba-993a6d77406c)'
detection:
    selection:
        EventID: 1121
        ProcessName|endswith:
          - '\wmiprvse.exe'
          - '\psexesvc.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```