---
title: "Powershell Detect Virtualization Environment"
aliases:
  - "/rule/d93129cd-1ee0-479f-bc03-ca6f129882e3"
ruleid: d93129cd-1ee0-479f-bc03-ca6f129882e3

tags:
  - attack.defense_evasion
  - attack.t1497.001



status: experimental





date: Tue, 3 Aug 2021 08:30:26 +0200


---

Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1497.001/T1497.001.md
* https://techgenix.com/malicious-powershell-scripts-evade-detection/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_detect_vm_env.yml))
```yaml
title: Powershell Detect Virtualization Environment
id: d93129cd-1ee0-479f-bc03-ca6f129882e3
status: experimental
author: frack113, Duc.Le-GTSC
date: 2021/08/03
modified: 2022/03/03
description: Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1497.001/T1497.001.md
    - https://techgenix.com/malicious-powershell-scripts-evade-detection/
tags:
    - attack.defense_evasion
    - attack.t1497.001
logsource:
    product: windows
    category: ps_script
    definition: EnableScriptBlockLogging must be set to enable
detection:
    selection_action:
        ScriptBlockText|contains: 
            - Get-WmiObject
            - gwmi
    selection_module:
        ScriptBlockText|contains: 
            - MSAcpi_ThermalZoneTemperature
            - Win32_ComputerSystem
    condition: all of selection*
falsepositives:
    - Unknown
level: medium

```
