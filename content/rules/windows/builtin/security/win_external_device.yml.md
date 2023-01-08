---
title: "External Disk Drive Or USB Storage Device"
aliases:
  - "/rule/f69a87ea-955e-4fb4-adb2-bb9fd6685632"
ruleid: f69a87ea-955e-4fb4-adb2-bb9fd6685632

tags:
  - attack.t1091
  - attack.t1200
  - attack.lateral_movement
  - attack.initial_access



status: experimental





date: Wed, 20 Nov 2019 16:07:29 -0600


---

Detects external diskdrives or plugged in USB devices , EventID 6416 on windows 10 or later

<!--more-->


## Known false-positives

* Legitimate administrative activity




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_external_device.yml))
```yaml
title: External Disk Drive Or USB Storage Device
id: f69a87ea-955e-4fb4-adb2-bb9fd6685632
description: Detects external diskdrives or plugged in USB devices , EventID 6416 on windows 10 or later
status: experimental
author: Keith Wright
date: 2019/11/20
modified: 2021/08/09
tags:
    - attack.t1091
    - attack.t1200
    - attack.lateral_movement
    - attack.initial_access
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 6416
        ClassName: 'DiskDrive'  
    selection2:
        DeviceDescription: 'USB Mass Storage Device'
    condition: selection or selection2
falsepositives: 
    - Legitimate administrative activity
level: low

```
