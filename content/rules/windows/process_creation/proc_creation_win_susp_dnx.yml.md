---
title: "Application Whitelisting Bypass via Dnx.exe"
aliases:
  - "/rule/81ebd28b-9607-4478-bf06-974ed9d53ed7"
ruleid: 81ebd28b-9607-4478-bf06-974ed9d53ed7

tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.t1027.004



status: test





date: Sat, 26 Oct 2019 19:58:45 +0200


---

Execute C# code located in the consoleapp folder

<!--more-->


## Known false-positives

* Legitimate use of dnx.exe by legitimate user



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml
* https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_dnx.yml))
```yaml
title: Application Whitelisting Bypass via Dnx.exe
id: 81ebd28b-9607-4478-bf06-974ed9d53ed7
status: test
description: Execute C# code located in the consoleapp folder
author: Beyu Denis, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml
  - https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/
date: 2019/10/26
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\dnx.exe'
  condition: selection
falsepositives:
  - Legitimate use of dnx.exe by legitimate user
level: medium
tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.t1027.004

```
