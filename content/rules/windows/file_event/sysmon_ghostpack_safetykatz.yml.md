---
title: "Detection of SafetyKatz"
aliases:
  - "/rule/e074832a-eada-4fd7-94a1-10642b130e16"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.001



date: Tue, 24 Jul 2018 23:51:46 +0200


---

Detects possible SafetyKatz Behaviour

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/GhostPack/SafetyKatz


## Raw rule
```yaml
title: Detection of SafetyKatz
id: e074832a-eada-4fd7-94a1-10642b130e16
status: experimental
description: Detects possible SafetyKatz Behaviour
references:
    - https://github.com/GhostPack/SafetyKatz
tags:
    - attack.credential_access
    - attack.t1003         # an old one
    - attack.t1003.001
author: Markus Neis
date: 2018/07/24
modified: 2020/08/23
logsource:
    category: file_event
    product: windows
detection:
    selection:        
        TargetFilename: '*\Temp\debug.bin'
    condition: selection
falsepositives:
    - Unknown
level: high

```
