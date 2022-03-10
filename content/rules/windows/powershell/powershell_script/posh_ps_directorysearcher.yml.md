---
title: "DirectorySearcher Powershell Exploitation"
aliases:
  - "/rule/1f6399cf-2c80-4924-ace1-6fcff3393480"


tags:
  - attack.discovery
  - attack.t1018



status: experimental





date: Sat, 12 Feb 2022 15:53:13 +0100


---

Enumerates Active Directory to determine computers that are joined to the domain

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md#atomic-test-15---enumerate-domain-computers-within-active-directory-using-directorysearcher


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_directorysearcher.yml))
```yaml
title: DirectorySearcher Powershell Exploitation
id: 1f6399cf-2c80-4924-ace1-6fcff3393480
status: experimental
description: Enumerates Active Directory to determine computers that are joined to the domain
date: 2022/02/12
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md#atomic-test-15---enumerate-domain-computers-within-active-directory-using-directorysearcher
author: frack113
logsource:
    product: windows
    category: ps_script
    definition: Script Block Logging must be enable
detection:
  selection:
      ScriptBlockText|contains|all: 
        - 'New-Object '
        - 'System.DirectoryServices.DirectorySearcher'
        - '.PropertiesToLoad.Add'
        - '.findall()'
        - 'Properties.name'
  condition: selection
falsepositives:
    - Unknown
level: medium
tags:
    - attack.discovery
    - attack.t1018

```
