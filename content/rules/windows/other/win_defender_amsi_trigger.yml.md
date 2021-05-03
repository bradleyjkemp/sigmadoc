---
title: "Windows Defender AMSI Trigger Detected"
aliases:
  - "/rule/ea9bf0fa-edec-4fb8-8b78-b119f2528186"



date: Mon, 14 Sep 2020 18:10:38 +0545


---

Detects triggering of AMSI by Windows Defender.

<!--more-->


## Known false-positives

* unlikely



## References

* https://docs.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps


## Raw rule
```yaml
title: Windows Defender AMSI Trigger Detected
id: ea9bf0fa-edec-4fb8-8b78-b119f2528186
description: Detects triggering of AMSI by Windows Defender.
date: 2020/09/14
author: Bhabesh Raj
references:
    - https://docs.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps
status: stable
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID: 1116
        DetectionSource: 'AMSI'
    condition: selection
falsepositives:
    - unlikely
level: high
```
