---
title: "Suspicious PowerShell Invocations - Generic"
aliases:
  - "/rule/3d304fda-78aa-43ed-975c-d740798a49c1"
ruleid: 3d304fda-78aa-43ed-975c-d740798a49c1

tags:
  - attack.execution
  - attack.t1059.001



status: deprecated





date: Sun, 12 Mar 2017 17:06:53 +0100


---

Detects suspicious PowerShell invocation command parameters

<!--more-->


## Known false-positives

* Penetration tests
* Very special / sneaky PowerShell scripts




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/deprecated/powershell_suspicious_invocation_generic.yml))
```yaml
title: Suspicious PowerShell Invocations - Generic
id: 3d304fda-78aa-43ed-975c-d740798a49c1
status: deprecated
description: Detects suspicious PowerShell invocation command parameters
tags:
    - attack.execution
    - attack.t1059.001
author: Florian Roth (rule)
date: 2017/03/12
modified: 2021/12/02
logsource:
    product: windows
    service: powershell
detection:
    selection_encoded:
        - ' -enc '
        - ' -EncodedCommand '
    selection_hidden:
        - ' -w hidden '
        - ' -window hidden '
        - ' -windowstyle hidden '
    selection_noninteractive:
        - ' -noni '
        - ' -noninteractive '
    condition: all of selection*
falsepositives:
    - Penetration tests
    - Very special / sneaky PowerShell scripts
level: high

```
