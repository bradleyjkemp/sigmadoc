---
title: "Create Volume Shadow Copy with Powershell"
aliases:
  - "/rule/afd12fed-b0ec-45c9-a13d-aa86625dac81"


tags:
  - attack.credential_access
  - attack.t1003.003



status: experimental





date: Wed, 12 Jan 2022 20:27:56 +0100


---

Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information

<!--more-->


## Known false-positives

* Legitimate PowerShell scripts



## References

* https://attack.mitre.org/datasources/DS0005/
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1&viewFallbackFrom=powershell-7


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_create_volume_shadow_copy.yml))
```yaml
title: Create Volume Shadow Copy with Powershell
id: afd12fed-b0ec-45c9-a13d-aa86625dac81
status: experimental
description: Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information
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
        ScriptBlockText|contains|all:
            - win32_shadowcopy
            - ').Create('
            - ClientAccessible
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: high
tags:
    - attack.credential_access
    - attack.t1003.003 

```
