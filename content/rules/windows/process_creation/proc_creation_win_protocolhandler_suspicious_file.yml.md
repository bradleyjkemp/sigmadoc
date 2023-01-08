---
title: "ProtocolHandler.exe Downloaded Suspicious File"
aliases:
  - "/rule/104cdb48-a7a8-4ca7-a453-32942c6e5dcb"
ruleid: 104cdb48-a7a8-4ca7-a453-32942c6e5dcb

tags:
  - attack.defense_evasion
  - attack.t1218



status: experimental





date: Tue, 13 Jul 2021 12:19:07 +0200


---

Emulates attack via documents through protocol handler in Microsoft Office. On successful execution you should see Microsoft Word launch a blank file.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_protocolhandler_suspicious_file.yml))
```yaml
title: ProtocolHandler.exe Downloaded Suspicious File
id: 104cdb48-a7a8-4ca7-a453-32942c6e5dcb
status: experimental
author: frack113
date: 2021/07/13
description: Emulates attack via documents through protocol handler in Microsoft Office. On successful execution you should see Microsoft Word launch a blank file.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\protocolhandler.exe'
        CommandLine|contains|all:
            - '"ms-word'
            - '.docx"'
    condition: selection 
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium

```
