---
title: "PowerShell ShellCode"
aliases:
  - "/rule/16b37b70-6fcf-4814-a092-c36bd3aafcbd"


tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1055
  - attack.execution
  - attack.t1059.001



status: experimental





date: Sat, 17 Nov 2018 09:10:09 +0100


---

Detects Base64 encoded Shellcode

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/cyb3rops/status/1063072865992523776


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_shellcode_b64.yml))
```yaml
title: PowerShell ShellCode
id: 16b37b70-6fcf-4814-a092-c36bd3aafcbd
status: experimental
description: Detects Base64 encoded Shellcode
references:
    - https://twitter.com/cyb3rops/status/1063072865992523776
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055
    - attack.execution
    - attack.t1059.001
author: David Ledbetter (shellcode), Florian Roth (rule)
date: 2018/11/17
modified: 2021/10/16
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains: 'AAAAYInlM'
    selection2:
        ScriptBlockText|contains:
            - 'OiCAAAAYInlM'
            - 'OiJAAAAYInlM'
    condition: selection and selection2
falsepositives:
    - Unknown
level: critical

```
