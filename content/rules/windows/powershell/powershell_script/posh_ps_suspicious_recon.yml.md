---
title: "Recon Information for Export with PowerShell"
aliases:
  - "/rule/a9723fcc-881c-424c-8709-fd61442ab3c3"


tags:
  - attack.collection
  - attack.t1119



status: experimental





date: Wed, 28 Jul 2021 13:17:40 +0200


---

Once established within a system or network, an adversary may use automated techniques for collecting internal data

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_recon.yml))
```yaml
title: Recon Information for Export with PowerShell
id: a9723fcc-881c-424c-8709-fd61442ab3c3
status: experimental
author: frack113
date: 2021/07/30
modified: 2021/12/02
description: Once established within a system or network, an adversary may use automated techniques for collecting internal data
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md
tags:
    - attack.collection
    - attack.t1119
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection_action:
        ScriptBlockText|contains:
            - 'Get-Service '
            - 'Get-ChildItem '
            - 'Get-Process '
    selection_redirect:
        ScriptBlockText|contains: '> $env:TEMP\'
    condition: all of selection*
falsepositives:
    - Unknown
level: medium

```
