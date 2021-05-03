---
title: "Application Whitelisting Bypass via Dnx.exe"
aliases:
  - "/rule/81ebd28b-9607-4478-bf06-974ed9d53ed7"

tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.t1027.004
  - attack.execution



date: Sat, 26 Oct 2019 19:58:45 +0200


---

Execute C# code located in the consoleapp folder

<!--more-->


## Known false-positives

* Legitimate use of dnx.exe by legitimate user



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml
* https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/


## Raw rule
```yaml
title: Application Whitelisting Bypass via Dnx.exe
id: 81ebd28b-9607-4478-bf06-974ed9d53ed7
status: experimental
description: Execute C# code located in the consoleapp folder
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml
    - https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/
author: Beyu Denis, oscd.community
date: 2019/10/26
modified: 2020/08/30
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.t1027.004
    - attack.execution      # an old one
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\dnx.exe'
    condition: selection
falsepositives:
    - Legitimate use of dnx.exe by legitimate user

```