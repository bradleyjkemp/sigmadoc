---
title: "Volume Shadow Copy Mount"
aliases:
  - "/rule/f512acbf-e662-4903-843e-97ce4652b740"
ruleid: f512acbf-e662-4903-843e-97ce4652b740

tags:
  - attack.credential_access
  - attack.t1003.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects volume shadow copy mount

<!--more-->


## Known false-positives

* Legitimate use of volume shadow copy mounts (backups maybe).



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_volume_shadow_copy_mount.yml))
```yaml
title: Volume Shadow Copy Mount
id: f512acbf-e662-4903-843e-97ce4652b740
description: Detects volume shadow copy mount
status: experimental
date: 2020/10/20
modified: 2021/10/13
author: Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR)
tags:
    - attack.credential_access
    - attack.t1003.002
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy
logsource:
    product: windows
    service: system
detection:
    selection: 
        Provider_Name: Microsoft-Windows-Ntfs
        EventID: 98
        DeviceName|contains: HarddiskVolumeShadowCopy
    condition: selection
falsepositives:
    - Legitimate use of volume shadow copy mounts (backups maybe).
level: low

```
