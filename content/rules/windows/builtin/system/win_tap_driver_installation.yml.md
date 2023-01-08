---
title: "Tap Driver Installation"
aliases:
  - "/rule/8e4cf0e5-aa5d-4dc3-beff-dc26917744a9"
ruleid: 8e4cf0e5-aa5d-4dc3-beff-dc26917744a9

tags:
  - attack.exfiltration
  - attack.t1048



status: experimental





date: Fri, 25 Oct 2019 04:30:55 +0200


---

Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques

<!--more-->


## Known false-positives

* Legitimate OpenVPN TAP insntallation




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_tap_driver_installation.yml))
```yaml
title: Tap Driver Installation
id: 8e4cf0e5-aa5d-4dc3-beff-dc26917744a9
description: Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques
status: experimental
author: Daniil Yugoslavskiy, Ian Davis, oscd.community
date: 2019/10/24
modified: 2021/11/30
tags:
    - attack.exfiltration
    - attack.t1048
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|contains: 'tap0901'
    condition: selection
falsepositives:
    - Legitimate OpenVPN TAP insntallation
level: medium
```
