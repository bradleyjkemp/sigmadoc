---
title: "Suspicious PowerShell Parameter Substring"
aliases:
  - "/rule/36210e0d-5b19-485d-a087-c096088885f0"

tags:
  - attack.execution
  - attack.t1086
  - attack.t1059.001



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious PowerShell invocation with a parameter substring

<!--more-->


## Known false-positives

* Penetration tests



## References

* http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier


## Raw rule
```yaml
title: Suspicious PowerShell Parameter Substring
id: 36210e0d-5b19-485d-a087-c096088885f0
status: experimental
description: Detects suspicious PowerShell invocation with a parameter substring
references:
    - http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier
tags:
    - attack.execution
    - attack.t1086 # an old one
    - attack.t1059.001
author: Florian Roth (rule), Daniel Bohannon (idea), Roberto Rodriguez (Fix)
date: 2019/01/16
modified: 2020/07/14
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\Powershell.exe'
        CommandLine|contains:
            - ' -windowstyle h '
            - ' -windowstyl h'
            - ' -windowsty h'
            - ' -windowst h'
            - ' -windows h'
            - ' -windo h'
            - ' -wind h'
            - ' -win h'
            - ' -wi h'
            - ' -win h '
            - ' -win hi '
            - ' -win hid '
            - ' -win hidd '
            - ' -win hidde '
            - ' -NoPr '
            - ' -NoPro '
            - ' -NoProf '
            - ' -NoProfi '
            - ' -NoProfil '
            - ' -nonin '
            - ' -nonint '
            - ' -noninte '
            - ' -noninter '
            - ' -nonintera '
            - ' -noninterac '
            - ' -noninteract '
            - ' -noninteracti '
            - ' -noninteractiv '
            - ' -ec '
            - ' -encodedComman '
            - ' -encodedComma '
            - ' -encodedComm '
            - ' -encodedCom '
            - ' -encodedCo '
            - ' -encodedC '
            - ' -encoded '
            - ' -encode '
            - ' -encod '
            - ' -enco '
            - ' -en '
    condition: selection
falsepositives:
    - Penetration tests
level: high

```
