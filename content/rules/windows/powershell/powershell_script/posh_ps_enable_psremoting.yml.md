---
title: "Enable Windows Remote Management"
aliases:
  - "/rule/991a9744-f2f0-44f2-bd33-9092eba17dc3"
ruleid: 991a9744-f2f0-44f2-bd33-9092eba17dc3

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

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.006/T1021.006.md#atomic-test-1---enable-windows-remote-management
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-7.2


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_enable_psremoting.yml))
```yaml
title: Enable Windows Remote Management
id: 991a9744-f2f0-44f2-bd33-9092eba17dc3
status: experimental
description: Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user. 
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.006/T1021.006.md#atomic-test-1---enable-windows-remote-management
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-7.2
author: frack113
date: 2022/01/07
logsource:
    product: windows
    category: ps_script
    definition: 'Script block logging must be enabled'
detection:
    selection_cmdlet:
        ScriptBlockText|contains: 'Enable-PSRemoting '
    condition: selection_cmdlet
falsepositives:
    - legitim script
level: medium
tags:
    - attack.lateral_movement
    - attack.t1021.006

```
