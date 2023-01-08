---
title: "Svchost DLL Search Order Hijack"
aliases:
  - "/rule/602a1f13-c640-4d73-b053-be9a2fa58b77"
ruleid: 602a1f13-c640-4d73-b053-be9a2fa58b77

tags:
  - attack.persistence
  - attack.defense_evasion
  - attack.t1574.002
  - attack.t1574.001



status: test





date: Mon, 28 Oct 2019 12:03:03 +0100


---

IKEEXT and SessionEnv service, as they call LoadLibrary on files that do not exist within C:\Windows\System32\ by default. An attacker can place their malicious logic within the PROCESS_ATTACH block of their library and restart the aforementioned services "svchost.exe -k netsvcs" to gain code execution on a remote machine.

<!--more-->


## Known false-positives

* Pentest



## References

* https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_svchost_dll_search_order_hijack.yml))
```yaml
title: Svchost DLL Search Order Hijack
id: 602a1f13-c640-4d73-b053-be9a2fa58b77
status: test
description: IKEEXT and SessionEnv service, as they call LoadLibrary on files that do not exist within C:\Windows\System32\ by default. An attacker can place their malicious logic within the PROCESS_ATTACH block of their library and restart the aforementioned services "svchost.exe -k netsvcs" to gain code execution on a remote machine.
author: SBousseaden
references:
  - https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992
date: 2019/10/28
modified: 2021/11/27
logsource:
  category: image_load
  product: windows
detection:
  selection:
    Image|endswith:
      - '\svchost.exe'
    ImageLoaded|endswith:
      - '\tsmsisrv.dll'
      - '\tsvipsrv.dll'
      - '\wlbsctrl.dll'
  filter:
    ImageLoaded|startswith:
      - 'C:\Windows\WinSxS\'
  condition: selection and not filter
falsepositives:
  - Pentest
level: high
tags:
  - attack.persistence
  - attack.defense_evasion
  - attack.t1574.002
  - attack.t1574.001

```
