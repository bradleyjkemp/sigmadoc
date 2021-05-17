---
title: "Detection of PowerShell Execution via DLL"
aliases:
  - "/rule/6812a10b-60ea-420c-832f-dfcc33b646ba"

tags:
  - attack.defense_evasion
  - attack.t1085
  - attack.t1218.011



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects PowerShell Strings applied to rundll as seen in PowerShdll.dll

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/p3nt4/PowerShdll/blob/master/README.md


## Raw rule
```yaml
title: Detection of PowerShell Execution via DLL
id: 6812a10b-60ea-420c-832f-dfcc33b646ba
status: experimental
description: Detects PowerShell Strings applied to rundll as seen in PowerShdll.dll
references:
    - https://github.com/p3nt4/PowerShdll/blob/master/README.md
tags:
    - attack.defense_evasion
    - attack.t1085          # an old one
    - attack.t1218.011
author: Markus Neis
date: 2018/08/25
modified: 2020/09/01
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image:
            - '*\rundll32.exe'
    selection2:
        Description:
            - '*Windows-Hostprozess (Rundll32)*'
    selection3:
        CommandLine:
            - '*Default.GetString*'
            - '*FromBase64String*'
    condition: (selection1 or selection2) and selection3
falsepositives:
    - Unknown
level: high

```
