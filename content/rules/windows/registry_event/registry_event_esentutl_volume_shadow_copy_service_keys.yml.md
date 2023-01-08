---
title: "Esentutl Volume Shadow Copy Service Keys"
aliases:
  - "/rule/5aad0995-46ab-41bd-a9ff-724f41114971"
ruleid: 5aad0995-46ab-41bd-a9ff-724f41114971

tags:
  - attack.credential_access
  - attack.t1003.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the volume shadow copy service initialization and processing via esentutl. Registry keys such as HKLM\\System\\CurrentControlSet\\Services\\VSS\\Diag\\VolSnap\\Volume are captured.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_esentutl_volume_shadow_copy_service_keys.yml))
```yaml
title: Esentutl Volume Shadow Copy Service Keys 
id: 5aad0995-46ab-41bd-a9ff-724f41114971
description: Detects the volume shadow copy service initialization and processing via esentutl. Registry keys such as HKLM\\System\\CurrentControlSet\\Services\\VSS\\Diag\\VolSnap\\Volume are captured.
status: experimental
date: 2020/10/20
modified: 2021/12/08
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
tags:
    - attack.credential_access
    - attack.t1003.002
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains: 'System\CurrentControlSet\Services\VSS'
        Image|endswith: 'esentutl.exe' # limit esentutl as in references, too many FP to filter
    filter:
        TargetObject|contains: 'System\CurrentControlSet\Services\VSS\Start'        
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
