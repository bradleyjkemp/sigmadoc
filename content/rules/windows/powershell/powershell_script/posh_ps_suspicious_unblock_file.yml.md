---
title: "Suspicious Unblock-File"
aliases:
  - "/rule/5947497f-1aa4-41dd-9693-c9848d58727d"


tags:
  - attack.defense_evasion
  - attack.t1553.005



status: experimental





date: Sat, 15 Jan 2022 17:04:03 +0100


---

Remove the Zone.Identifier alternate data stream which identifies the file as downloaded from the internet.

<!--more-->


## Known false-positives

* Legitimate PowerShell scripts



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1553.005/T1553.005.md#atomic-test-3---remove-the-zoneidentifier-alternate-data-stream
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file?view=powershell-7.2


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_unblock_file.yml))
```yaml
title: Suspicious Unblock-File
id: 5947497f-1aa4-41dd-9693-c9848d58727d
status: experimental
description: Remove the Zone.Identifier alternate data stream which identifies the file as downloaded from the internet.
date: 2022/02/01
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1553.005/T1553.005.md#atomic-test-3---remove-the-zoneidentifier-alternate-data-stream
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file?view=powershell-7.2
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Unblock-File '
            - '-Path '
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: medium
tags:
    - attack.defense_evasion
    - attack.t1553.005

```
