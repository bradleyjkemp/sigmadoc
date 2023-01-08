---
title: "Potential RDP Exploit CVE-2019-0708"
aliases:
  - "/rule/aaa5b30d-f418-420b-83a0-299cb6024885"
ruleid: aaa5b30d-f418-420b-83a0-299cb6024885

tags:
  - attack.lateral_movement
  - attack.t1210
  - car.2013-07-002



status: experimental





date: Fri, 24 May 2019 10:01:19 +0200


---

Detect suspicious error on protocol RDP, potential CVE-2019-0708

<!--more-->


## Known false-positives

* Bad connections or network interruptions



## References

* https://github.com/zerosum0x0/CVE-2019-0708
* https://github.com/Ekultek/BlueKeep


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_rdp_potential_cve_2019_0708.yml))
```yaml
title: Potential RDP Exploit CVE-2019-0708
id: aaa5b30d-f418-420b-83a0-299cb6024885
description: Detect suspicious error on protocol RDP, potential CVE-2019-0708
references:
    - https://github.com/zerosum0x0/CVE-2019-0708
    - https://github.com/Ekultek/BlueKeep
tags:
    - attack.lateral_movement
    - attack.t1210
    - car.2013-07-002
status: experimental
author: 'Lionel PRAT, Christophe BROCAS, @atc_project (improvements)'
date: 2019/05/24
modified: 2021/10/13
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID:
            - 56
            - 50
        Provider_Name: TermDD
    condition: selection
falsepositives:
    - Bad connections or network interruptions
level: medium  # too many false positives

```
