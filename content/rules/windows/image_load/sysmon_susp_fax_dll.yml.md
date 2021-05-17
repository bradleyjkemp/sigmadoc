---
title: "Fax Service DLL Search Order Hijack"
aliases:
  - "/rule/828af599-4c53-4ed2-ba4a-a9f835c434ea"

tags:
  - attack.persistence
  - attack.defense_evasion
  - attack.t1073
  - attack.t1038
  - attack.t1574.001
  - attack.t1574.002



status: experimental



level: high



date: Wed, 1 Jul 2020 10:58:39 +0200


---

The Fax service attempts to load ualapi.dll, which is non-existent. An attacker can then (side)load their own malicious DLL using this service.

<!--more-->


## Known false-positives

* Unlikely



## References

* https://windows-internals.com/faxing-your-way-to-system/


## Raw rule
```yaml
title: Fax Service DLL Search Order Hijack
id: 828af599-4c53-4ed2-ba4a-a9f835c434ea
status: experimental
description: The Fax service attempts to load ualapi.dll, which is non-existent. An attacker can then (side)load their own malicious DLL using this service.
references:
    - https://windows-internals.com/faxing-your-way-to-system/
author: NVISO
date: 2020/05/04
modified: 2020/08/23
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1073          # an old one
    - attack.t1038          # an old one
    - attack.t1574.001
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith:
        - fxssvc.exe
        ImageLoaded|endswith:
        - ualapi.dll
    filter:
        ImageLoaded|startswith:
        - C:\Windows\WinSxS\
    condition: selection and not filter
falsepositives:
    - Unlikely
level: high

```
