---
title: "CrackMapExec PowerShell Obfuscation"
aliases:
  - "/rule/6f8b3439-a203-45dc-a88b-abf57ea15ccf"

tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027.005
  - attack.t1027
  - attack.t1086



date: Fri, 5 Jun 2020 13:18:03 -0400


---

The CrachMapExec pentesting framework implements a PowerShell obfuscation with some static strings detected by this rule.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/byt3bl33d3r/CrackMapExec
* https://github.com/byt3bl33d3r/CrackMapExec/blob/0a49f75347b625e81ee6aa8c33d3970b5515ea9e/cme/helpers/powershell.py#L242


## Raw rule
```yaml
title: CrackMapExec PowerShell Obfuscation
id: 6f8b3439-a203-45dc-a88b-abf57ea15ccf
status: experimental
description: The CrachMapExec pentesting framework implements a PowerShell obfuscation with some static strings detected by this rule.
references:
    - https://github.com/byt3bl33d3r/CrackMapExec
    - https://github.com/byt3bl33d3r/CrackMapExec/blob/0a49f75347b625e81ee6aa8c33d3970b5515ea9e/cme/helpers/powershell.py#L242
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027.005
    - attack.t1027      # an old one
    - attack.t1086      # an old one
author: Thomas Patzke
date: 2020/05/22
logsource:
    category: process_creation
    product: windows
detection:
    powershell_execution:
        CommandLine|contains: 'powershell.exe'
    snippets:
        CommandLine|contains:
            - 'join*split'
            # Line 343ff
            - "( $ShellId[1]+$ShellId[13]+'x')"
            - '( $PSHome[*]+$PSHOME[*]+'
            - "( $env:Public[13]+$env:Public[5]+'x')"
            - "( $env:ComSpec[4,*,25]-Join'')"
            - "[1,3]+'x'-Join'')"
    condition: powershell_execution and snippets
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Unknown
level: high

```