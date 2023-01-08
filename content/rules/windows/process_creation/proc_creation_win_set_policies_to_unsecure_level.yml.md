---
title: "Change PowerShell Policies to an Unsecure Level"
aliases:
  - "/rule/87e3c4e8-a6a8-4ad9-bb4f-46e7ff99a180"
ruleid: 87e3c4e8-a6a8-4ad9-bb4f-46e7ff99a180

tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Wed, 20 Oct 2021 12:58:43 +0200


---

Detects use of executionpolicy option to set a unsecure policies

<!--more-->


## Known false-positives

* Administrator script



## References

* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.1
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.1
* https://adsecurity.org/?p=2604
* https://thedfirreport.com/2021/11/01/from-zero-to-domain-admin/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_set_policies_to_unsecure_level.yml))
```yaml
title: Change PowerShell Policies to an Unsecure Level
id: 87e3c4e8-a6a8-4ad9-bb4f-46e7ff99a180
description: Detects use of executionpolicy option to set a unsecure policies
status: experimental
references:
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.1
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.1
    - https://adsecurity.org/?p=2604
    - https://thedfirreport.com/2021/11/01/from-zero-to-domain-admin/
tags:
    - attack.execution
    - attack.t1059.001
author: frack113
date: 2021/11/01
modified: 2022/02/23
logsource:
    product: windows
    category: process_creation
detection:
    option:
        CommandLine|contains:
            - ' -executionpolicy '
            - ' -ep '
            - ' -exec '
    level:
        CommandLine|contains:
            - 'Unrestricted'
            - 'bypass'
            - 'RemoteSigned'
    condition: option and level
falsepositives:
    - Administrator script
level: medium

```
