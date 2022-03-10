---
title: "Suspicious Ntdll Pipe Redirection"
aliases:
  - "/rule/bbc865e4-7fcd-45a6-8ff1-95ced28ec5b2"


tags:
  - attack.defense_evasion



status: experimental





date: Sat, 5 Mar 2022 10:39:33 +0100


---

Detects command that type the content of ntdll.dll to a different file or a pipe in order to evade AV / EDR detection

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.x86matthew.com/view_post?id=ntdll_pipe


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_ntdll_type_redirect.yml))
```yaml
title: Suspicious Ntdll Pipe Redirection
id: bbc865e4-7fcd-45a6-8ff1-95ced28ec5b2
status: experimental
description: Detects command that type the content of ntdll.dll to a different file or a pipe in order to evade AV / EDR detection
references:
    - https://www.x86matthew.com/view_post?id=ntdll_pipe
tags:
    - attack.defense_evasion
author: Florian Roth 
date: 2022/03/05
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'type %windir%\system32\ntdll.dll'
            - 'type %systemroot%\system32\ntdll.dll'
            - 'type c:\windows\system32\ntdll.dll'
            - '\\ntdll.dll > \\\\.\\pipe\\'
    condition: selection
falsepositives:
    - Unknown
level: high

```
