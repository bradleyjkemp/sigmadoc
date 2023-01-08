---
title: "Execute Invoke-command on Remote Host"
aliases:
  - "/rule/7b836d7f-179c-4ba4-90a7-a7e60afb48e6"
ruleid: 7b836d7f-179c-4ba4-90a7-a7e60afb48e6

tags:
  - attack.lateral_movement
  - attack.t1021.006



status: experimental





date: Sat, 8 Jan 2022 09:17:56 +0100


---

Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.

<!--more-->


## Known false-positives

* legitim script



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.006/T1021.006.md#atomic-test-2---invoke-command
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-7.2


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_invoke_command_remote.yml))
```yaml
title: Execute Invoke-command on Remote Host
id: 7b836d7f-179c-4ba4-90a7-a7e60afb48e6
status: experimental
description: Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user. 
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.006/T1021.006.md#atomic-test-2---invoke-command
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-7.2
author: frack113
date: 2022/01/07
logsource:
    product: windows
    category: ps_script
    definition: 'Script block logging must be enabled'
detection:
    selection_cmdlet:
        ScriptBlockText|contains|all:
            - 'invoke-command '
            - ' -ComputerName '
    condition: selection_cmdlet
falsepositives:
    - legitim script
level: medium
tags:
    - attack.lateral_movement
    - attack.t1021.006

```
