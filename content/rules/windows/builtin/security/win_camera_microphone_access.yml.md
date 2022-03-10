---
title: "Processes Accessing the Microphone and Webcam"
aliases:
  - "/rule/8cd538a4-62d5-4e83-810b-12d41e428d6e"


tags:
  - attack.collection
  - attack.t1123



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Potential adversaries accessing the microphone and webcam in an endpoint.

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/duzvik/status/1269671601852813320
* https://medium.com/@7a616368/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_camera_microphone_access.yml))
```yaml
title: Processes Accessing the Microphone and Webcam
id: 8cd538a4-62d5-4e83-810b-12d41e428d6e
status: test
description: Potential adversaries accessing the microphone and webcam in an endpoint.
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
references:
  - https://twitter.com/duzvik/status/1269671601852813320
  - https://medium.com/@7a616368/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072
date: 2020/06/07
modified: 2021/11/27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4657
      - 4656
      - 4663
    ObjectName|contains:
        - '\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged'
        - '\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged'
  condition: selection
falsepositives:
  - Unknown
level: medium
tags:
  - attack.collection
  - attack.t1123

```