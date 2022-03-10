---
title: "PowerShell ADRecon Execution"
aliases:
  - "/rule/bf72941a-cba0-41ea-b18c-9aca3925690d"


tags:
  - attack.discovery
  - attack.execution
  - attack.t1059.001



status: experimental





date: Fri, 16 Jul 2021 12:58:47 +0545


---

Detects execution of ADRecon.ps1 for AD reconnaissance which has been reported to be actively used by FIN7

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/sense-of-security/ADRecon
* https://bi-zone.medium.com/from-pentest-to-apt-attack-cybercriminal-group-fin7-disguises-its-malware-as-an-ethical-hackers-c23c9a75e319


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_adrecon_execution.yml))
```yaml
title: PowerShell ADRecon Execution
id: bf72941a-cba0-41ea-b18c-9aca3925690d
status: experimental
description: Detects execution of ADRecon.ps1 for AD reconnaissance which has been reported to be actively used by FIN7 
references:
    - https://github.com/sense-of-security/ADRecon
    - https://bi-zone.medium.com/from-pentest-to-apt-attack-cybercriminal-group-fin7-disguises-its-malware-as-an-ethical-hackers-c23c9a75e319
tags:
    - attack.discovery
    - attack.execution
    - attack.t1059.001
author: Bhabesh Raj
date: 2021/07/16
modified: 2021/10/16
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains:
            - 'Function Get-ADRExcelComOb'
            - 'ADRecon-Report.xlsx' #Default
    condition: selection
falsepositives:
    - Unknown
level: high

```
