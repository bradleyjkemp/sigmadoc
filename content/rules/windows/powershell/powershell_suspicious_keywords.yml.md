---
title: "Suspicious PowerShell Keywords"
aliases:
  - "/rule/1f49f2ab-26bc-48b3-96cc-dcffbc93eadf"

tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1086



date: Mon, 11 Feb 2019 13:02:33 +0100


---

Detects keywords that could indicate the use of some PowerShell exploitation framework

<!--more-->


## Known false-positives

* Penetration tests



## References

* https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462
* https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1
* https://github.com/hlldz/Invoke-Phant0m/blob/master/Invoke-Phant0m.ps1


## Raw rule
```yaml
title: Suspicious PowerShell Keywords
id: 1f49f2ab-26bc-48b3-96cc-dcffbc93eadf
status: experimental
description: Detects keywords that could indicate the use of some PowerShell exploitation framework
date: 2019/02/11
author: Florian Roth, Perez Diego (@darkquassar)
references:
    - https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462
    - https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1
    - https://github.com/hlldz/Invoke-Phant0m/blob/master/Invoke-Phant0m.ps1
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086  #an old one
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277. Monitor for EventID 4104'
detection:
    keywords:
        Message:
            - "System.Reflection.Assembly.Load"
            - "[System.Reflection.Assembly]::Load"
            - "[Reflection.Assembly]::Load"
            - "System.Reflection.AssemblyName"
            - "Reflection.Emit.AssemblyBuilderAccess"
            - "Runtime.InteropServices.DllImportAttribute"
            - "SuspendThread"
    condition: keywords
falsepositives:
    - Penetration tests
level: high

```