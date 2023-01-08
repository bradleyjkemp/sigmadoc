---
title: "SilentProcessExit Monitor Registrytion for LSASS"
aliases:
  - "/rule/55e29995-75e7-451a-bef0-6225e2f13597"
ruleid: 55e29995-75e7-451a-bef0-6225e2f13597

tags:
  - attack.credential_access
  - attack.t1003.007



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects changes to the Registry in which a monitor program gets registered to dump process memory of the lsass.exe process memory

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.deepinstinct.com/2021/02/16/lsass-memory-dumps-are-stealthier-than-ever-before-part-2/
* https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_silentprocessexit_lsass.yml))
```yaml
title: SilentProcessExit Monitor Registrytion for LSASS
id: 55e29995-75e7-451a-bef0-6225e2f13597
description: Detects changes to the Registry in which a monitor program gets registered to dump process memory of the lsass.exe process memory
status: experimental
author: Florian Roth
references:
    - https://www.deepinstinct.com/2021/02/16/lsass-memory-dumps-are-stealthier-than-ever-before-part-2/
    - https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
date: 2021/02/26
tags:
    - attack.credential_access
    - attack.t1003.007
logsource:
    category: registry_event
    product: windows
detection:
    selection:       
        TargetObject|contains: 'Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
