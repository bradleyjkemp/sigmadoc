---
title: "Powershell LocalAccount Manipulation"
aliases:
  - "/rule/4fdc44df-bfe9-4fcc-b041-68f5a2d3031c"
ruleid: 4fdc44df-bfe9-4fcc-b041-68f5a2d3031c

tags:
  - attack.persistence
  - attack.t1098



status: experimental





date: Wed, 29 Dec 2021 17:47:43 +0100


---

Adversaries may manipulate accounts to maintain access to victim systems.
Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups


<!--more-->


## Known false-positives

* legitimate administrative script



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md#atomic-test-1---admin-account-manipulate
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/?view=powershell-5.1


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_localuser.yml))
```yaml
title: Powershell LocalAccount Manipulation
id: 4fdc44df-bfe9-4fcc-b041-68f5a2d3031c
status: experimental
description: |
  Adversaries may manipulate accounts to maintain access to victim systems.
  Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md#atomic-test-1---admin-account-manipulate
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/?view=powershell-5.1
author: frack113
date: 2021/12/28
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains:
            - 'Disable-LocalUser'
            - 'Enable-LocalUser'
            - 'Get-LocalUser'
            - 'Set-LocalUser'
            - 'New-LocalUser'
            - 'Rename-LocalUser'
            - 'Remove-LocalUser'
    condition: selection
falsepositives:
  - legitimate administrative script
level: medium
tags:
  - attack.persistence
  - attack.t1098

```
