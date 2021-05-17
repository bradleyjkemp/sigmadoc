---
title: "Windows Registry Persistence COM Search Order Hijacking"
aliases:
  - "/rule/a0ff33d8-79e4-4cef-b4f3-9dc4133ccd12"

tags:
  - attack.persistence
  - attack.t1038
  - attack.t1574.001



status: experimental



level: medium



date: Tue, 14 Apr 2020 12:47:52 +0200


---

Detects potential COM object hijacking leveraging the COM Search Order

<!--more-->


## Known false-positives

* Some installed utilities (i.e. OneDrive) may serve new COM objects at user-level



## References

* https://www.cyberbit.com/blog/endpoint-security/com-hijacking-windows-overlooked-security-vulnerability/


## Raw rule
```yaml
title: Windows Registry Persistence COM Search Order Hijacking
id: a0ff33d8-79e4-4cef-b4f3-9dc4133ccd12
status: experimental
description: Detects potential COM object hijacking leveraging the COM Search Order
references:
    - https://www.cyberbit.com/blog/endpoint-security/com-hijacking-windows-overlooked-security-vulnerability/
author: Maxime Thiebaut (@0xThiebaut)
date: 2020/04/14
modified: 2020/09/06
tags:
    - attack.persistence
    - attack.t1038 # an old one
    - attack.t1574.001
logsource:
    category: registry_event
    product: windows
detection:
    selection: # Detect new COM servers in the user hive
        TargetObject: 'HKU\\*_Classes\CLSID\\*\InProcServer32\(Default)'
    filter:
        Details: # Exclude privileged directories and observed FPs
            - '%%systemroot%%\system32\\*'
            - '%%systemroot%%\SysWow64\\*'
            - '*\AppData\Local\Microsoft\OneDrive\\*\FileCoAuthLib64.dll'
            - '*\AppData\Local\Microsoft\OneDrive\\*\FileSyncShell64.dll'
            - '*\AppData\Local\Microsoft\TeamsMeetingAddin\\*\Microsoft.Teams.AddinLoader.dll'
    condition: selection and not filter
falsepositives:
    - Some installed utilities (i.e. OneDrive) may serve new COM objects at user-level
level: medium

```
