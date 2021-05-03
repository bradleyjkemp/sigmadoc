---
title: "Tap Driver Installation"
aliases:
  - "/rule/8e4cf0e5-aa5d-4dc3-beff-dc26917744a9"

tags:
  - attack.exfiltration
  - attack.t1048



date: Fri, 25 Oct 2019 04:30:55 +0200


---

Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques

<!--more-->


## Known false-positives

* Legitimate OpenVPN TAP insntallation




## Raw rule
```yaml
action: global
title: Tap Driver Installation
id: 8e4cf0e5-aa5d-4dc3-beff-dc26917744a9
description: Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques
status: experimental
author: Daniil Yugoslavskiy, Ian Davis, oscd.community
date: 2019/10/24
tags:
    - attack.exfiltration
    - attack.t1048
falsepositives:
    - Legitimate OpenVPN TAP insntallation
level: medium
detection:
    selection_1:
        ImagePath|contains: 'tap0901'
    condition: selection and selection_1
---
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 6
---
 logsource:
     product: windows
     service: security
 detection:
     selection:
         EventID: 4697

```
