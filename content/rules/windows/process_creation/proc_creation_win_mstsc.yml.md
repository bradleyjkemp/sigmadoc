---
title: "Remote Desktop Protocol Use Mstsc"
aliases:
  - "/rule/954f0af7-62dd-418f-b3df-a84bc2c7a774"
ruleid: 954f0af7-62dd-418f-b3df-a84bc2c7a774

tags:
  - attack.lateral_movement
  - attack.t1021.001



status: experimental





date: Sat, 8 Jan 2022 09:17:56 +0100


---

Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.

<!--more-->


## Known false-positives

* Unknow



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md#t1021001---remote-desktop-protocol
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_mstsc.yml))
```yaml
title: Remote Desktop Protocol Use Mstsc
id: 954f0af7-62dd-418f-b3df-a84bc2c7a774
status: experimental
description: Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user. 
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md#t1021001---remote-desktop-protocol
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc
date: 2022/01/07
logsource:
    category: process_creation
    product: windows
detection:
    selection_mstsc:
        Image|endswith: \mstsc.exe
        CommandLine|contains: ' /v:'
    selection_cmdkey:
        Image|endswith: \cmdkey.exe
        CommandLine|contains|all:
            - '/generic:'
            - '/user:'
            - '/pass:'
    condition: 1 of selection_*
falsepositives:
    - Unknow
level: medium
tags:
    - attack.lateral_movement
    - attack.t1021.001
```
