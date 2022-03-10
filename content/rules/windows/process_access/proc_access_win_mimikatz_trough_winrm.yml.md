---
title: "Mimikatz through Windows Remote Management"
aliases:
  - "/rule/aa35a627-33fb-4d04-a165-d33b4afca3e8"


tags:
  - attack.credential_access
  - attack.execution
  - attack.t1003.001
  - attack.t1059.001
  - attack.lateral_movement
  - attack.t1021.006
  - attack.s0002



status: stable





date: Mon, 20 May 2019 12:25:58 +0200


---

Detects usage of mimikatz through WinRM protocol by monitoring access to lsass process by wsmprovhost.exe.

<!--more-->


## Known false-positives

* low



## References

* https://pentestlab.blog/2018/05/15/lateral-movement-winrm/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_mimikatz_trough_winrm.yml))
```yaml
title: Mimikatz through Windows Remote Management
id: aa35a627-33fb-4d04-a165-d33b4afca3e8
description: Detects usage of mimikatz through WinRM protocol by monitoring access to lsass process by wsmprovhost.exe.
references:
    - https://pentestlab.blog/2018/05/15/lateral-movement-winrm/
status: stable
author: Patryk Prauze - ING Tech
date: 2019/05/20
modified: 2021/06/21
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        SourceImage: 'C:\Windows\system32\wsmprovhost.exe'
    filter:
        GrantedAccess: '0x80000000'
    condition: selection and not filter
tags:
    - attack.credential_access
    - attack.execution
    - attack.t1003.001
    - attack.t1059.001
    - attack.lateral_movement
    - attack.t1021.006
    - attack.s0002
falsepositives:
    - low
level: high

```
