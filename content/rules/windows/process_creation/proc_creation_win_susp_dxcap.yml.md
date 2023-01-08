---
title: "Application Whitelisting Bypass via Dxcap.exe"
aliases:
  - "/rule/60f16a96-db70-42eb-8f76-16763e333590"
ruleid: 60f16a96-db70-42eb-8f76-16763e333590

tags:
  - attack.defense_evasion
  - attack.t1218



status: test





date: Sat, 26 Oct 2019 08:16:08 +0200


---

Detects execution of of Dxcap.exe

<!--more-->


## Known false-positives

* Legitimate execution of dxcap.exe by legitimate user



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml
* https://twitter.com/harr0ey/status/992008180904419328


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_dxcap.yml))
```yaml
title: Application Whitelisting Bypass via Dxcap.exe
id: 60f16a96-db70-42eb-8f76-16763e333590
status: test
description: Detects execution of of Dxcap.exe
author: Beyu Denis, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml
  - https://twitter.com/harr0ey/status/992008180904419328
date: 2019/10/26
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\dxcap.exe'
    CommandLine|contains|all:
      - '-c'
      - '.exe'
  condition: selection
falsepositives:
  - Legitimate execution of dxcap.exe by legitimate user
level: medium
tags:
  - attack.defense_evasion
  - attack.t1218

```
