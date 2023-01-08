---
title: "Hidden Powershell in Link File Pattern"
aliases:
  - "/rule/30e92f50-bb5a-4884-98b5-d20aa80f3d7a"
ruleid: 30e92f50-bb5a-4884-98b5-d20aa80f3d7a

tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Sun, 6 Feb 2022 14:01:48 +0100


---

Detects events that appear when a user click on a link file with a powershell command in it

<!--more-->


## Known false-positives

* Legitimate commands in .lnk files



## References

* https://www.x86matthew.com/view_post?id=embed_exe_lnk


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_embed_exe_lnk.yml))
```yaml
title: Hidden Powershell in Link File Pattern
id: 30e92f50-bb5a-4884-98b5-d20aa80f3d7a
status: experimental
description: Detects events that appear when a user click on a link file with a powershell command in it
author: frack113
date: 2022/02/06
references:
    - https://www.x86matthew.com/view_post?id=embed_exe_lnk
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: C:\Windows\explorer.exe
        Image: C:\Windows\System32\cmd.exe
        CommandLine|contains|all:
            - 'powershell'
            - '.lnk'
    condition: selection
falsepositives:
    - Legitimate commands in .lnk files
level: medium
tags:
    - attack.execution
    - attack.t1059.001 

```
