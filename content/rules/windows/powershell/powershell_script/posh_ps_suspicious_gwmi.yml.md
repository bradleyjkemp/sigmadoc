---
title: "Suspicious Get-WmiObject"
aliases:
  - "/rule/0332a266-b584-47b4-933d-a00b103e1b37"


tags:
  - attack.persistence
  - attack.t1546



status: experimental





date: Wed, 12 Jan 2022 20:27:56 +0100


---

The infrastructure for management data and operations that enables local and remote management of Windows personal computers and servers

<!--more-->


## Known false-positives

* Legitimate PowerShell scripts



## References

* https://attack.mitre.org/datasources/DS0005/
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1&viewFallbackFrom=powershell-7


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_gwmi.yml))
```yaml
title: Suspicious Get-WmiObject
id: 0332a266-b584-47b4-933d-a00b103e1b37
status: experimental
description: The infrastructure for management data and operations that enables local and remote management of Windows personal computers and servers
date: 2022/01/12
author: frack113
references:
    - https://attack.mitre.org/datasources/DS0005/
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1&viewFallbackFrom=powershell-7
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains:
            - Get-WmiObject
            - gwmi
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: low
tags:
    - attack.persistence
    - attack.t1546

```
