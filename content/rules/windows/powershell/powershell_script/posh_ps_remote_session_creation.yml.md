---
title: "PowerShell Remote Session Creation"
aliases:
  - "/rule/a0edd39f-a0c6-4c17-8141-261f958e8d8f"
ruleid: a0edd39f-a0c6-4c17-8141-261f958e8d8f

tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Sat, 8 Jan 2022 09:17:56 +0100


---

Adversaries may abuse PowerShell commands and scripts for execution.
PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system


<!--more-->


## Known false-positives

* legitimate administrative script



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-10---powershell-invoke-downloadcradle
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7.2


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_remote_session_creation.yml))
```yaml
title: PowerShell Remote Session Creation
id: a0edd39f-a0c6-4c17-8141-261f958e8d8f
status: experimental
description: |
  Adversaries may abuse PowerShell commands and scripts for execution.
  PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-10---powershell-invoke-downloadcradle
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7.2
author: frack113
date: 2022/01/06
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains|all:
            - New-PSSession
            - '-ComputerName '
    condition: selection
falsepositives:
  - legitimate administrative script
level: medium
tags:
  - attack.execution
  - attack.t1059.001

```
