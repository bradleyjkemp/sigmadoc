---
title: "Use Remove-Item to Delete File"
aliases:
  - "/rule/b8af5f36-1361-4ebe-9e76-e36128d947bf"


tags:
  - attack.defense_evasion
  - attack.t1070.004



status: experimental





date: Sat, 15 Jan 2022 17:04:03 +0100


---

Powershell Remove-Item  with -Path to delete a file or a folder with "-Recurse"

<!--more-->


## Known false-positives

* Legitimate PowerShell scripts



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/Remove-Item?view=powershell-5.1&viewFallbackFrom=powershell-7


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_remove_item_path.yml))
```yaml
title: Use Remove-Item to Delete File
id: b8af5f36-1361-4ebe-9e76-e36128d947bf
status: experimental
description: Powershell Remove-Item  with -Path to delete a file or a folder with "-Recurse"
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/Remove-Item?view=powershell-5.1&viewFallbackFrom=powershell-7
date: 2022/01/15
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains|all:
            - Remove-Item
            - '-Path '
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: low
tags:
    - attack.defense_evasion
    - attack.t1070.004

```
