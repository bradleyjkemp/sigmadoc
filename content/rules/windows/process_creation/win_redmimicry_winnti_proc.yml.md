---
title: "RedMimicry Winnti Playbook Execute"
aliases:
  - "/rule/95022b85-ff2a-49fa-939a-d7b8f56eeb9b"

tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1059
  - attack.t1106
  - attack.t1059.003
  - attack.t1218.011





level: high



date: Wed, 1 Jul 2020 09:17:31 +0200


---

Detects actions caused by the RedMimicry Winnti playbook

<!--more-->


## Known false-positives

* Unknown



## References

* https://redmimicry.com


## Raw rule
```yaml
title: RedMimicry Winnti Playbook Execute
id: 95022b85-ff2a-49fa-939a-d7b8f56eeb9b
description: Detects actions caused by the RedMimicry Winnti playbook
references:
    - https://redmimicry.com
author: Alexander Rausch
date: 2020/06/24
modified: 2020/09/06
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059 # an old one
    - attack.t1106
    - attack.t1059.003
    - attack.t1218.011    
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|contains:
            - rundll32.exe
            - cmd.exe
        CommandLine|contains:
            - gthread-3.6.dll
            - \Windows\Temp\tmp.bat
            - sigcmm-2.4.dll
    condition: selection
falsepositives:
    - Unknown
level: high

```
