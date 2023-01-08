---
title: "Malicious ShellIntel PowerShell Commandlets"
aliases:
  - "/rule/402e1e1d-ad59-47b6-bf80-1ee44985b3a7"
ruleid: 402e1e1d-ad59-47b6-bf80-1ee44985b3a7

tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Mon, 16 Aug 2021 09:10:05 +0200


---

Detects Commandlet names from ShellIntel exploitation scripts.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Shellntel/scripts/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_shellintel_malicious_commandlets.yml))
```yaml
title: Malicious ShellIntel PowerShell Commandlets
id: 402e1e1d-ad59-47b6-bf80-1ee44985b3a7
status: experimental
description: Detects Commandlet names from ShellIntel exploitation scripts.
date: 2021/08/09
modified: 2021/10/16
references:
    - https://github.com/Shellntel/scripts/
tags:
    - attack.execution
    - attack.t1059.001
author: Max Altgelt, Tobias Michalski
logsource:
    product: windows
    category: ps_script
    definition: Script Block Logging must be enable
detection:
  selection:
      ScriptBlockText|contains:
        - Invoke-SMBAutoBrute
        - Invoke-GPOLinks
        - Out-Minidump
        - Invoke-Potato
  condition: selection
falsepositives:
    - Unknown
level: high

```
