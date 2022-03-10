---
title: "Monitoring For Persistence Via BITS"
aliases:
  - "/rule/b9cbbc17-d00d-4e3d-a827-b06d03d2380d"


tags:
  - attack.defense_evasion
  - attack.t1197



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

BITS will allow you to schedule a command to execute after a successful download to notify you that the job is finished. When the job runs on the system the command specified in the BITS job will be executed. This can be abused by actors to create a backdoor within the system and for persistence. It will be chained in a BITS job to schedule the download of malware/additional binaries and execute the program after being downloaded

<!--more-->


## Known false-positives

* None observed yet.



## References

* https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
* http://0xthem.blogspot.com/2014/03/t-emporal-persistence-with-and-schtasks.html
* https://isc.sans.edu/diary/Wipe+the+drive+Stealthy+Malware+Persistence+Mechanism+-+Part+1/15394


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_monitoring_for_persistence_via_bits.yml))
```yaml
title: Monitoring For Persistence Via BITS
id: b9cbbc17-d00d-4e3d-a827-b06d03d2380d
description: BITS will allow you to schedule a command to execute after a successful download to notify you that the job is finished. When the job runs on the system the command specified in the BITS job will be executed. This can be abused by actors to create a backdoor within the system and for persistence. It will be chained in a BITS job to schedule the download of malware/additional binaries and execute the program after being downloaded
status: experimental
author: Sreeman
date: 2020/10/29
modified: 2022/03/07
references:
    - https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
    - http://0xthem.blogspot.com/2014/03/t-emporal-persistence-with-and-schtasks.html
    - https://isc.sans.edu/diary/Wipe+the+drive+Stealthy+Malware+Persistence+Mechanism+-+Part+1/15394
logsource:
    product: windows
    category: process_creation
detection:
    selection_1:
        CommandLine|contains|all:
            - 'bitsadmin'
            - '/SetNotifyCmdLine'
        CommandLine|contains:  
            - '%COMSPEC%'
            - 'cmd.exe'
            - 'regsvr32.exe'
    selection_2:
        CommandLine|contains|all:
            - 'bitsadmin'
            - '/Addfile'
        CommandLine|contains:    
            - 'http:'
            - 'https:'
            - 'ftp:'
            - 'ftps:'
    condition: 1 of selection_*
falsepositives:
    - None observed yet.
fields:
    - CommandLine
level: medium
tags:
    - attack.defense_evasion
    - attack.t1197

```
