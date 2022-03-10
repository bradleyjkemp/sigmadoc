---
title: "Ncat Execution"
aliases:
  - "/rule/e31033fc-33f0-4020-9a16-faf9b31cbf08"


tags:
  - attack.command_and_control
  - attack.t1095



status: experimental





date: Wed, 21 Jul 2021 10:55:54 +0200


---

Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network

<!--more-->


## Known false-positives

* Legitimate ncat use



## References

* https://nmap.org/ncat/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1095/T1095.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_netcat_execution.yml))
```yaml
title: Ncat Execution
id: e31033fc-33f0-4020-9a16-faf9b31cbf08
status: experimental
author: frack113, Florian Roth
date: 2021/07/21
modified: 2022/02/23
description: Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network
references:
    - https://nmap.org/ncat/   
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1095/T1095.md
tags:
    - attack.command_and_control
    - attack.t1095
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # can not use OriginalFileName as is empty
        Image|endswith:
            - '\ncat.exe'
            - '\netcat.exe'
    selection_cmdline:
        # Typical command lines
        CommandLine|contains:
            - ' -lvp '
            - ' -l -v -p '
            - ' -lv -p '
            - ' -l --proxy-type http '
            - ' --exec cmd.exe '
            - ' -vnl --exec '
    condition: selection or selection_cmdline
falsepositives:
    - Legitimate ncat use
level: high

```
