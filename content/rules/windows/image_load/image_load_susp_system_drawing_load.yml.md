---
title: "Suspicious System.Drawing Load"
aliases:
  - "/rule/666ecfc7-229d-42b8-821e-1a8f8cb7057c"
ruleid: 666ecfc7-229d-42b8-821e-1a8f8cb7057c

tags:
  - attack.collection
  - attack.t1113



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

A General detection for processes loading System.Drawing.ni.dll. This could be an indicator of potential Screen Capture.

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/OTRF/detection-hackathon-apt29/issues/16
* https://threathunterplaybook.com/evals/apt29/detections/7.A.1_3B4E5808-3C71-406A-B181-17B0CE3178C9.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_susp_system_drawing_load.yml))
```yaml
title: Suspicious System.Drawing Load
id: 666ecfc7-229d-42b8-821e-1a8f8cb7057c
description: A General detection for processes loading System.Drawing.ni.dll. This could be an indicator of potential Screen Capture.
status: experimental
date: 2020/05/02
modified: 2021/12/05
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
tags:
    - attack.collection
    - attack.t1113
references:
    - https://github.com/OTRF/detection-hackathon-apt29/issues/16
    - https://threathunterplaybook.com/evals/apt29/detections/7.A.1_3B4E5808-3C71-406A-B181-17B0CE3178C9.html
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded|endswith: '\System.Drawing.ni.dll'
    filter:
        # The number of false positives was too high - we had to do this broader filter 
        # based on the following paths that shouldn't be writable to an unprivileged user
        Image|startswith:
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
            - 'C:\Windows\System32\'
            - 'C:\Windows\Microsoft.NET\'
            - 'C:\Windows\ImmersiveControlPanel\'
    filter2:
        Image:
            - 'C:\Users\\*\AppData\Local\NhNotifSys\nahimic\nahimicNotifSys.exe'
            - 'C:\Users\\*\GitHubDesktop\Update.exe'
            - 'C:\Windows\System32\NhNotifSys.exe'
    condition: selection and not 1 of filter*
falsepositives:
    - unknown
level: low  # too many false positives
```