---
title: "Delete Volume Shadow Copies Via WMI With PowerShell"
aliases:
  - "/rule/87df9ee1-5416-453a-8a08-e8d4a51e9ce1"


tags:
  - attack.impact
  - attack.t1490



status: stable





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Shadow Copies deletion using operating systems utilities via PowerShell

<!--more-->


## Known false-positives

* Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md
* https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_shadow_copies_deletion.yml
* https://www.fortinet.com/blog/threat-research/stomping-shadow-copies-a-second-look-into-deletion-methods


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_classic/posh_pc_delete_volume_shadow_copies.yml))
```yaml
title: Delete Volume Shadow Copies Via WMI With PowerShell
id: 87df9ee1-5416-453a-8a08-e8d4a51e9ce1
description: Shadow Copies deletion using operating systems utilities via PowerShell
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md
    - https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_shadow_copies_deletion.yml
    - https://www.fortinet.com/blog/threat-research/stomping-shadow-copies-a-second-look-into-deletion-methods
tags:
    - attack.impact
    - attack.t1490
status: stable
author: frack113
date: 2021/06/03
modified: 2021/10/16
logsource:
    product: windows
    category: ps_classic_start
    definition: fields have to be extract from event
detection:
    selection_obj:
        HostApplication|contains|all:
            - 'Get-WmiObject'
            - ' Win32_Shadowcopy'
    selection_del:
        HostApplication|contains:
            - 'Delete()'
            - 'Remove-WmiObject'
    condition: selection_obj and selection_del
fields:
    - HostApplication
falsepositives:
    - Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason
level: critical

```
