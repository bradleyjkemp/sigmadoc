---
title: "RedMimicry Winnti Playbook Dropped File"
aliases:
  - "/rule/130c9e58-28ac-4f83-8574-0a4cc913b97e"

tags:
  - attack.defense_evasion
  - attack.t1027





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
title: RedMimicry Winnti Playbook Dropped File
id: 130c9e58-28ac-4f83-8574-0a4cc913b97e
description: Detects actions caused by the RedMimicry Winnti playbook
references:
    - https://redmimicry.com
author: Alexander Rausch
date: 2020/06/24
tags:
    - attack.defense_evasion
    - attack.t1027
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - gthread-3.6.dll
            - sigcmm-2.4.dll
            - \Windows\Temp\tmp.bat
    condition: selection
falsepositives:
    - Unknown
level: high

```
