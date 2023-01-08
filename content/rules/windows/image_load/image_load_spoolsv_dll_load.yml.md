---
title: "Windows Spooler Service Suspicious Binary Load"
aliases:
  - "/rule/02fb90de-c321-4e63-a6b9-25f4b03dfd14"
ruleid: 02fb90de-c321-4e63-a6b9-25f4b03dfd14

tags:
  - attack.persistence
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1574
  - cve.2021.1675
  - cve.2021.34527



status: experimental





date: Thu, 1 Jul 2021 12:12:09 +0545


---

Detect DLL Load from Spooler Service backup folder

<!--more-->


## Known false-positives

* Loading of legitimate driver



## References

* https://github.com/hhlxf/PrintNightmare
* https://github.com/ly4k/SpoolFool


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_spoolsv_dll_load.yml))
```yaml
title: Windows Spooler Service Suspicious Binary Load
id: 02fb90de-c321-4e63-a6b9-25f4b03dfd14
status: experimental
description: Detect DLL Load from Spooler Service backup folder
references:
    - https://github.com/hhlxf/PrintNightmare
    - https://github.com/ly4k/SpoolFool
author: FPT.EagleEye, Thomas Patzke (improvements)
date: 2021/06/29
modified: 2022/02/09
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: 'spoolsv.exe'
        ImageLoaded|contains: 
            - '\Windows\System32\spool\drivers\x64\3\'
            - '\Windows\System32\spool\drivers\x64\4\'
        ImageLoaded|endswith: '.dll'
    condition: selection
falsepositives:
    - Loading of legitimate driver
level: informational
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1574
    - cve.2021.1675
    - cve.2021.34527
```
