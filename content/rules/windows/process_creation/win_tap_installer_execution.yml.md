---
title: "Tap Installer Execution"
aliases:
  - "/rule/99793437-3e16-439b-be0f-078782cf953d"

tags:
  - attack.exfiltration
  - attack.t1048



status: experimental



level: medium



date: Fri, 25 Oct 2019 04:30:55 +0200


---

Well-known TAP software installation. Possible preparation for data exfiltration using tunneling techniques

<!--more-->


## Known false-positives

* Legitimate OpenVPN TAP insntallation




## Raw rule
```yaml
title: Tap Installer Execution
id: 99793437-3e16-439b-be0f-078782cf953d
description: Well-known TAP software installation. Possible preparation for data exfiltration using tunneling techniques
status: experimental
author: Daniil Yugoslavskiy, Ian Davis, oscd.community
date: 2019/10/24
tags:
    - attack.exfiltration
    - attack.t1048
logsource:
     category: process_creation
     product: windows
detection:
    selection:
        Image|endswith: '\tapinstall.exe'
    condition: selection
falsepositives:
    - Legitimate OpenVPN TAP insntallation
level: medium

```
