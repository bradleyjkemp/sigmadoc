---
title: "SVCHOST Credential Dump"
aliases:
  - "/rule/174afcfa-6e40-4ae9-af64-496546389294"


tags:
  - attack.t1548



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects when a process, such as mimikatz, accesses the memory of svchost to dump credentials

<!--more-->


## Known false-positives

* Non identified legit exectubale




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_svchost_cred_dump.yml))
```yaml
title: SVCHOST Credential Dump
id: 174afcfa-6e40-4ae9-af64-496546389294
description: Detects when a process, such as mimikatz, accesses the memory of svchost to dump credentials
status: experimental
date: 2021/04/30
author: Florent Labouyrie
logsource:
    product: windows
    category: process_access
tags:
    - attack.t1548
detection:
    selection_process:
        TargetImage|endswith: '\svchost.exe'
    selection_memory:
        GrantedAccess: '0x143a'
    filter_trusted_process_access:
        SourceImage|endswith: 
          - '*\services.exe'
          - '*\msiexec.exe'
    condition: selection_process and selection_memory and not filter_trusted_process_access
falsepositives:
    - Non identified legit exectubale
level: critical

```