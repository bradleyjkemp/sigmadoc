---
title: "External Disk Drive or USB Storage Device"
aliases:
  - "/rule/f69a87ea-955e-4fb4-adb2-bb9fd6685632"

tags:
  - attack.t1091
  - attack.t1200
  - attack.lateral_movement
  - attack.initial_access



date: Wed, 20 Nov 2019 16:07:29 -0600


---

Detects external diskdrives or plugged in USB devices

<!--more-->


## Known false-positives

* Legitimate administrative activity




## Raw rule
```yaml
title: External Disk Drive or USB Storage Device
id: f69a87ea-955e-4fb4-adb2-bb9fd6685632
description: Detects external diskdrives or plugged in USB devices
status: experimental
author: Keith Wright
date: 2019/11/20
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
        EventID: 
            - 6416
        DeviceClassName: 'DiskDrive'  
    selection2:
        DeviceDescription: 'USB Mass Storage Device'
    condition: selection or selection2
falsepositives: 
    - Legitimate administrative activity
level: low

```