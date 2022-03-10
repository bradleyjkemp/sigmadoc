---
title: "Renamed ProcDump"
aliases:
  - "/rule/4a0b2c7e-7cb2-495d-8b63-5f268e7bfd67"


tags:
  - attack.defense_evasion
  - attack.t1036.003



status: experimental





date: Mon, 18 Nov 2019 15:27:04 +0100


---

Detects the execution of a renamed ProcDump executable often used by attackers or malware

<!--more-->


## Known false-positives

* Procdump illegaly bundled with legitimate software
* Weird admins who renamed binaries



## References

* https://docs.microsoft.com/en-us/sysinternals/downloads/procdump


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_renamed_procdump.yml))
```yaml
title: Renamed ProcDump
id: 4a0b2c7e-7cb2-495d-8b63-5f268e7bfd67
status: experimental
description: Detects the execution of a renamed ProcDump executable often used by attackers or malware
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/procdump
author: Florian Roth
date: 2019/11/18
modified: 2021/08/16
tags:
    - attack.defense_evasion
    - attack.t1036.003
logsource:
    product: windows
    category: process_creation
detection:
    selection1:
        OriginalFileName: 'procdump'
    selection2:
        CommandLine|contains|all: 
            - ' -ma '
            - ' -accepteula '
    selection3:
        CommandLine|contains|all: 
            - ' -ma '
            - '.dmp'
    filter:
        Image|endswith: 
            - '\procdump.exe'
            - '\procdump64.exe'
    condition: ( selection1 or selection2 or selection3 ) and not filter
falsepositives:
    - Procdump illegaly bundled with legitimate software
    - Weird admins who renamed binaries
level: critical

```
