---
title: "Process Dump via RdrLeakDiag.exe"
aliases:
  - "/rule/edadb1e5-5919-4e4c-8462-a9e643b02c4b"
ruleid: edadb1e5-5919-4e4c-8462-a9e643b02c4b

tags:
  - attack.credential_access
  - attack.t1003.001



status: experimental





date: Fri, 24 Sep 2021 18:22:06 +0200


---

Detects a process memory dump performed by RdrLeakDiag.exe

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.pureid.io/dumping-abusing-windows-credentials-part-1/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_process_dump_rdrleakdiag.yml))
```yaml
title: Process Dump via RdrLeakDiag.exe
id: edadb1e5-5919-4e4c-8462-a9e643b02c4b 
description: Detects a process memory dump performed by RdrLeakDiag.exe
status: experimental
level: high
references:
    - https://www.pureid.io/dumping-abusing-windows-credentials-part-1/
author: Cedric MAURUGEON
date: 2021/09/24
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: RdrLeakDiag.exe
        CommandLine|contains: fullmemdmp
    condition: selection
falsepositives: 
    - Unknown

```
