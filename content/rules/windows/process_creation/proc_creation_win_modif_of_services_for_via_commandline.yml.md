---
title: "Modification Of Existing Services For Persistence"
aliases:
  - "/rule/38879043-7e1e-47a9-8d46-6bec88e201df"
ruleid: 38879043-7e1e-47a9-8d46-6bec88e201df

tags:
  - attack.persistence
  - attack.t1543.003
  - attack.t1574.011



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects modification of an existing service on a compromised host in order to execute an arbitrary payload when the service is started or killed as a method of persistence.

<!--more-->


## Known false-positives

* unknown



## References

* https://pentestlab.blog/2020/01/22/persistence-modify-existing-service/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_modif_of_services_for_via_commandline.yml))
```yaml
title: Modification Of Existing Services For Persistence
id: 38879043-7e1e-47a9-8d46-6bec88e201df
description: Detects modification of an existing service on a compromised host in order to execute an arbitrary payload when the service is started or killed as a method of persistence.
references:
    - https://pentestlab.blog/2020/01/22/persistence-modify-existing-service/
status: experimental
tags:
    - attack.persistence
    - attack.t1543.003
    - attack.t1574.011
author: Sreeman
date: 2020/09/29
modified: 2022/03/06
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmdline_1:
        CommandLine|contains|all:
            - 'sc '
            - 'config '
            - 'binpath='
    selection_cmdline_2: 
        CommandLine|contains|all:
            - 'sc '
            - 'failure'
            - 'command='
    selection_cmdline_3:
        CommandLine|contains|all:
            - 'reg '
            - 'add '
            - 'FailureCommand'
        CommandLine|contains:
            - '.sh'
            - '.exe'
            - '.dll'
            - '.bin$'
            - '.bat'
            - '.cmd'
            - '.js'
            - '.msh$'
            - '.reg$'
            - '.scr'
            - '.ps'
            - '.vb'
            - '.jar'
            - '.pl'
    selection_cmdline_4:
        CommandLine|contains|all:
            - 'reg '
            - 'add '
            - 'ImagePath'
        CommandLine|contains:
            - '.sh'
            - '.exe'
            - '.dll'
            - '.bin$'
            - '.bat'
            - '.cmd'
            - '.js'
            - '.msh$'
            - '.reg$'
            - '.scr'
            - '.ps'
            - '.vb'
            - '.jar'
            - '.pl'
    condition: 1 of selection_cmdline_*
falsepositives:
    - unknown
level: medium

```
