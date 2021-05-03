---
title: "Audio Capture via PowerShell"
aliases:
  - "/rule/932fb0d8-692b-4b0f-a26e-5643a50fe7d6"

tags:
  - attack.collection
  - attack.t1123



date: Mon, 28 Oct 2019 11:59:49 +0100


---

Detects audio capture via PowerShell Cmdlet

<!--more-->


## Known false-positives

* Legitimate audio capture by legitimate user



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml
* https://eqllib.readthedocs.io/en/latest/analytics/ab7a6ef4-0983-4275-a4f1-5c6bd3c31c23.html


## Raw rule
```yaml
title: Audio Capture via PowerShell
id: 932fb0d8-692b-4b0f-a26e-5643a50fe7d6
description: Detects audio capture via PowerShell Cmdlet
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/ab7a6ef4-0983-4275-a4f1-5c6bd3c31c23.html
tags:
    - attack.collection
    - attack.t1123
detection:
    selection:
        CommandLine|contains: 'WindowsAudioDevice-Powershell-Cmdlet'
    condition: selection
falsepositives:
    - Legitimate audio capture by legitimate user
level: medium
logsource:
    category: process_creation
    product: windows

```