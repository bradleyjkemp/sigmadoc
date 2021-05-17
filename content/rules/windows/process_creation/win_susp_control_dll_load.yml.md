---
title: "Suspicious Control Panel DLL Load"
aliases:
  - "/rule/d7eb979b-c2b5-4a6f-a3a7-c87ce6763819"

tags:
  - attack.defense_evasion
  - attack.t1085
  - attack.t1218.011



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/rikvduijn/status/853251879320662017


## Raw rule
```yaml
title: Suspicious Control Panel DLL Load
id: d7eb979b-c2b5-4a6f-a3a7-c87ce6763819
status: experimental
description: Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits
author: Florian Roth
date: 2017/04/15
modified: 2020/09/05
references:
    - https://twitter.com/rikvduijn/status/853251879320662017
tags:
    - attack.defense_evasion
    - attack.t1085      # an old one
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\System32\control.exe'
        CommandLine: '*\rundll32.exe *'
    filter:
        CommandLine: '*Shell32.dll*'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```
