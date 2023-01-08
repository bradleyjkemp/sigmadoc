---
title: "Automated Collection Command PowerShell"
aliases:
  - "/rule/c1dda054-d638-4c16-afc8-53e007f3fbc5"
ruleid: c1dda054-d638-4c16-afc8-53e007f3fbc5

tags:
  - attack.collection
  - attack.t1119



status: experimental





date: Wed, 28 Jul 2021 13:17:40 +0200


---

Once established within a system or network, an adversary may use automated techniques for collecting internal data.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_automated_collection.yml))
```yaml
title: Automated Collection Command PowerShell
id: c1dda054-d638-4c16-afc8-53e007f3fbc5
status: experimental
author: frack113
date: 2021/07/28
modified: 2021/12/02
description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
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
    selection_ext:
        ScriptBlockText|contains:
            - '.doc'
            - '.docx'
            - '.xls'
            - '.xlsx'
            - '.ppt'
            - '.pptx'
            - '.rtf'
            - '.pdf'
            - '.txt'
    selection_cmd:
        ScriptBlockText|contains|all:
            - 'Get-ChildItem'
            - ' -Recurse '
            - ' -Include '
    condition: all of selection*
falsepositives:
    - Unknown
level: medium

```
