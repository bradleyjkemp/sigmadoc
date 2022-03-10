---
title: "Detection of SafetyKatz"
aliases:
  - "/rule/e074832a-eada-4fd7-94a1-10642b130e16"


tags:
  - attack.credential_access
  - attack.t1003.001



status: test





date: Tue, 24 Jul 2018 23:51:46 +0200


---

Detects possible SafetyKatz Behaviour

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/GhostPack/SafetyKatz


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_ghostpack_safetykatz.yml))
```yaml
title: Detection of SafetyKatz
id: e074832a-eada-4fd7-94a1-10642b130e16
status: test
description: Detects possible SafetyKatz Behaviour
author: Markus Neis
references:
  - https://github.com/GhostPack/SafetyKatz
date: 2018/07/24
modified: 2021/11/27
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith: '\Temp\debug.bin'
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.credential_access
  - attack.t1003.001

```
