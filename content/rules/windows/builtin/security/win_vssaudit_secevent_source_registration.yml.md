---
title: "VSSAudit Security Event Source Registration"
aliases:
  - "/rule/e9faba72-4974-4ab2-a4c5-46e25ad59e9b"
ruleid: e9faba72-4974-4ab2-a4c5-46e25ad59e9b

tags:
  - attack.credential_access
  - attack.t1003.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the registration of the security event source VSSAudit. It would usually trigger when volume shadow copy operations happen.

<!--more-->


## Known false-positives

* Legitimate use of VSSVC. Maybe backup operations. It would usually be done by C:\Windows\System32\VSSVC.exe.



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_vssaudit_secevent_source_registration.yml))
```yaml
title: VSSAudit Security Event Source Registration
id: e9faba72-4974-4ab2-a4c5-46e25ad59e9b
description: Detects the registration of the security event source VSSAudit. It would usually trigger when volume shadow copy operations happen.
status: experimental
date: 2020/10/20
modified: 2021/11/30
author: Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR)
tags:
    - attack.credential_access
    - attack.t1003.002
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy
logsource:
    product: windows
    service: security
detection:
    selection:
        Provider_Name: Microsoft-Windows-Security-Auditing
        AuditSourceName: VSSAudit
        EventID: 
            - 4904
            - 4905
    condition: selection
falsepositives:
    - Legitimate use of VSSVC. Maybe backup operations. It would usually be done by C:\Windows\System32\VSSVC.exe.
level: low
```
