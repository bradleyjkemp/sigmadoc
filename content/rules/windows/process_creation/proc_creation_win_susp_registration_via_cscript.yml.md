---
title: "Suspicious Registration via cscript.exe"
aliases:
  - "/rule/28c8f68b-098d-45af-8d43-8089f3e35403"


tags:
  - attack.defense_evasion
  - attack.t1218



status: experimental





date: Fri, 5 Nov 2021 18:12:57 -0500


---

Detects when the registration of a VSS/VDS Provider as a COM+ application.

<!--more-->


## Known false-positives

* None



## References

* https://twitter.com/sblmsrsn/status/1456613494783160325?s=20
* https://ss64.com/vb/cscript.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_registration_via_cscript.yml))
```yaml
title: Suspicious Registration via cscript.exe
id: 28c8f68b-098d-45af-8d43-8089f3e35403
description: Detects when the registration of a VSS/VDS Provider as a COM+ application.
status: experimental
author: Austin Songer @austinsonger
date: 2021/11/05
references:
- https://twitter.com/sblmsrsn/status/1456613494783160325?s=20
- https://ss64.com/vb/cscript.html
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith: '\cscript.exe'
        CommandLine|contains: '-register'
    selection2:
        CommandLine|contains:
            - '\Windows Kits\10\bin\10.0.22000.0\x64'
            - '\Windows Kits\10\bin\10.0.19041.0\x64'
            - '\Windows Kits\10\bin\10.0.17763.0\x64'
    condition:
        selection1 and selection2
fields:
    - CommandLine
    - ParentCommandLine
tags:
- attack.defense_evasion
- attack.t1218
level: medium
falsepositives:
- None

```
