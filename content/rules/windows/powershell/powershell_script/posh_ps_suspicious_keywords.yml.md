---
title: "Suspicious PowerShell Keywords"
aliases:
  - "/rule/1f49f2ab-26bc-48b3-96cc-dcffbc93eadf"


tags:
  - attack.execution
  - attack.t1059.001



status: experimental





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
* https://gist.github.com/MHaggis/0dbe00ad401daa7137c81c99c268cfb7


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_keywords.yml))
```yaml
title: Suspicious PowerShell Keywords
id: 1f49f2ab-26bc-48b3-96cc-dcffbc93eadf
status: experimental
description: Detects keywords that could indicate the use of some PowerShell exploitation framework
date: 2019/02/11
modified: 2021/10/16
author: Florian Roth, Perez Diego (@darkquassar)
references:
    - https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462
    - https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1
    - https://github.com/hlldz/Invoke-Phant0m/blob/master/Invoke-Phant0m.ps1
    - https://gist.github.com/MHaggis/0dbe00ad401daa7137c81c99c268cfb7
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled for 4104
detection:
    framework:
        ScriptBlockText|contains:
            - 'System.Reflection.Assembly.Load($'
            - '[System.Reflection.Assembly]::Load($'
            - '[Reflection.Assembly]::Load($'
            - 'System.Reflection.AssemblyName'
            - 'Reflection.Emit.AssemblyBuilderAccess'
            - 'Runtime.InteropServices.DllImportAttribute'
            - 'SuspendThread'
            - 'rundll32'
            # - 'FromBase64'
            - 'Invoke-WMIMethod'
            - 'http://127.0.0.1'
    condition: framework
falsepositives:
    - Penetration tests
level: high

```