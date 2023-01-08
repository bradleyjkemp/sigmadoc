---
title: "Suspicious Use of PsLogList"
aliases:
  - "/rule/aae1243f-d8af-40d8-ab20-33fc6d0c55bc"
ruleid: aae1243f-d8af-40d8-ab20-33fc6d0c55bc

tags:
  - attack.discovery
  - attack.t1087
  - attack.t1087.001
  - attack.t1087.002



status: experimental





date: Sat, 18 Dec 2021 21:52:05 +0100


---

Threat actors can use the PsLogList utility to dump event log in order to extract admin accounts and perform account discovery.

<!--more-->


## Known false-positives

* Another tool that uses the command line switches of PsLogList
* Legitimate use of PsLogList by an administrator



## References

* https://research.nccgroup.com/2021/01/12/abusing-cloud-services-to-fly-under-the-radar/
* https://www.cybereason.com/blog/deadringer-exposing-chinese-threat-actors-targeting-major-telcos
* https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Sysinternals/PsLogList


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_psloglist.yml))
```yaml
title: Suspicious Use of PsLogList
id: aae1243f-d8af-40d8-ab20-33fc6d0c55bc
description: Threat actors can use the PsLogList utility to dump event log in order to extract admin accounts and perform account discovery.
status: experimental
references:
    - https://research.nccgroup.com/2021/01/12/abusing-cloud-services-to-fly-under-the-radar/
    - https://www.cybereason.com/blog/deadringer-exposing-chinese-threat-actors-targeting-major-telcos
    - https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Sysinternals/PsLogList
author: Nasreddine Bencherchali @nas_bench
date: 2021/12/18
tags:
    - attack.discovery
    - attack.t1087
    - attack.t1087.001
    - attack.t1087.002
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        OriginalFileName|contains: 'psloglist'
    selection2:
        Image|endswith:
          - '\psloglist.exe'
          - '\psloglist64.exe'
    flags:
        CommandLine|contains:
          - '-d'
          - '/d'
          - '-x'
          - '/x'
          - '-s'
          - '/s'
    other:
        CommandLine|contains|all: 
            - 'security'
            - 'accepteula'
    condition: (1 of selection*) or (flags and other)
falsepositives:
    - Another tool that uses the command line switches of PsLogList
    - Legitimate use of PsLogList by an administrator
level: medium

```
