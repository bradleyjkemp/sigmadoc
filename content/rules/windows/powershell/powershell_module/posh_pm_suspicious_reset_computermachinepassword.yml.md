---
title: "Suspicious Computer Machine Password by PowerShell"
aliases:
  - "/rule/e3818659-5016-4811-a73c-dde4679169d2"


tags:
  - attack.initial_access
  - attack.t1078



status: experimental





date: Tue, 22 Feb 2022 13:44:51 +0100


---

The Reset-ComputerMachinePassword cmdlet changes the computer account password that the computers use to authenticate to the domain controllers in the domain. You can use it to reset the password of the local computer.

<!--more-->


## Known false-positives

* Administrator PowerShell scripts



## References

* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/reset-computermachinepassword?view=powershell-5.1
* https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_module/posh_pm_suspicious_reset_computermachinepassword.yml))
```yaml
title: Suspicious Computer Machine Password by PowerShell
id: e3818659-5016-4811-a73c-dde4679169d2
status: experimental
description: The Reset-ComputerMachinePassword cmdlet changes the computer account password that the computers use to authenticate to the domain controllers in the domain. You can use it to reset the password of the local computer.
references:
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/reset-computermachinepassword?view=powershell-5.1
    - https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/
author: frack113
date: 2022/02/21
logsource:
    product: windows
    category: ps_module
detection:
    selection:
        ContextInfo|contains: 'Reset-ComputerMachinePassword'
    condition: selection
falsepositives:
    - Administrator PowerShell scripts 
level: medium
tags:
    - attack.initial_access
    - attack.t1078
```
