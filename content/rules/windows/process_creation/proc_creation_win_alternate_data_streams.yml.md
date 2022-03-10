---
title: "Execute From Alternate Data Streams"
aliases:
  - "/rule/7f43c430-5001-4f8b-aaa9-c3b88f18fa5c"


tags:
  - attack.defense_evasion
  - attack.t1564.004



status: experimental





date: Wed, 1 Sep 2021 13:52:09 +0200


---

Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.004/T1564.004.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_alternate_data_streams.yml))
```yaml
title: Execute From Alternate Data Streams
id: 7f43c430-5001-4f8b-aaa9-c3b88f18fa5c
status: experimental
author: frack113
date: 2021/09/01
description: Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.004/T1564.004.md
tags:
    - attack.defense_evasion
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection_stream:
        CommandLine|contains: 'txt:'
    selection_tools_type:
        CommandLine|contains|all:
            - 'type '
            - ' > '
    selection_tools_makecab:
        CommandLine|contains|all:
            - 'makecab '
            - '.cab'
    selection_tools_reg:
        CommandLine|contains|all:
            - 'reg '
            - ' export '
    selection_tools_regedit:
        CommandLine|contains|all:
            - 'regedit '
            - ' /E '
    selection_tools_esentutl:
        CommandLine|contains|all:
            - 'esentutl '
            - ' /y '
            - ' /d '
            - ' /o '
    condition: selection_stream and (1 of selection_tools_*) 
falsepositives:
    - Unknown
level: medium

```
