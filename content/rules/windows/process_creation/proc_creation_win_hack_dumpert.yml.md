---
title: "Dumpert Process Dumper"
aliases:
  - "/rule/2704ab9e-afe2-4854-a3b1-0c0706d03578"
ruleid: 2704ab9e-afe2-4854-a3b1-0c0706d03578

tags:
  - attack.credential_access
  - attack.t1003.001



status: experimental





date: Tue, 4 Feb 2020 22:38:06 +0100


---

Detects the use of Dumpert process dumper, which dumps the lsass.exe process memory

<!--more-->


## Known false-positives

* Very unlikely



## References

* https://github.com/outflanknl/Dumpert
* https://unit42.paloaltonetworks.com/actors-still-exploiting-sharepoint-vulnerability/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_hack_dumpert.yml))
```yaml
title: Dumpert Process Dumper
id: 2704ab9e-afe2-4854-a3b1-0c0706d03578
status: experimental
description: Detects the use of Dumpert process dumper, which dumps the lsass.exe process memory
author: Florian Roth
references:
    - https://github.com/outflanknl/Dumpert
    - https://unit42.paloaltonetworks.com/actors-still-exploiting-sharepoint-vulnerability/
date: 2020/02/04
modified: 2021/12/08
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Hashes|contains: '09D278F9DE118EF09163C6140255C690'
    condition: selection
falsepositives:
    - Very unlikely
level: critical
```
