---
title: "Fax Service DLL Search Order Hijack"
aliases:
  - "/rule/828af599-4c53-4ed2-ba4a-a9f835c434ea"


tags:
  - attack.persistence
  - attack.defense_evasion
  - attack.t1574.001
  - attack.t1574.002



status: test





date: Wed, 1 Jul 2020 10:58:39 +0200


---

The Fax service attempts to load ualapi.dll, which is non-existent. An attacker can then (side)load their own malicious DLL using this service.

<!--more-->


## Known false-positives

* Unlikely



## References

* https://windows-internals.com/faxing-your-way-to-system/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_susp_fax_dll.yml))
```yaml
title: Fax Service DLL Search Order Hijack
id: 828af599-4c53-4ed2-ba4a-a9f835c434ea
status: test
description: The Fax service attempts to load ualapi.dll, which is non-existent. An attacker can then (side)load their own malicious DLL using this service.
author: NVISO
references:
  - https://windows-internals.com/faxing-your-way-to-system/
date: 2020/05/04
modified: 2021/11/27
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
tags:
  - attack.persistence
  - attack.defense_evasion
  - attack.t1574.001
  - attack.t1574.002

```
