---
title: "Suspicious New-PSDrive to Admin Share"
aliases:
  - "/rule/1c563233-030e-4a07-af8c-ee0490a66d3a"


tags:
  - attack.lateral_movement
  - attack.t1021.002



status: experimental





date: Sat, 1 Jan 2022 08:42:40 +0100


---

Adversaries may use to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md#atomic-test-2---map-admin-share-powershell
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-psdrive?view=powershell-7.2


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_new_psdrive.yml))
```yaml
title: Suspicious New-PSDrive to Admin Share
id: 1c563233-030e-4a07-af8c-ee0490a66d3a
description: Adversaries may use to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user. 
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md#atomic-test-2---map-admin-share-powershell
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-psdrive?view=powershell-7.2
status: experimental
author: frack113
date: 2022/01/01
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'New-PSDrive'
            - '-psprovider '
            - 'filesystem'
            - '-root '
            - '\\'
            - '$'
    condition: selection
falsepositives:
    - unknown
level: medium
tags:
    - attack.lateral_movement
    - attack.t1021.002
```
