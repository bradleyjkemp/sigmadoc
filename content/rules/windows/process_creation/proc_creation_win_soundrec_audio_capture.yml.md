---
title: "Audio Capture via SoundRecorder"
aliases:
  - "/rule/83865853-59aa-449e-9600-74b9d89a6d6e"


tags:
  - attack.collection
  - attack.t1123



status: test





date: Mon, 28 Oct 2019 11:59:49 +0100


---

Detect attacker collecting audio via SoundRecorder application.

<!--more-->


## Known false-positives

* Legitimate audio capture by legitimate user.



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.md
* https://eqllib.readthedocs.io/en/latest/analytics/f72a98cb-7b3d-4100-99c3-a138b6e9ff6e.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_soundrec_audio_capture.yml))
```yaml
title: Audio Capture via SoundRecorder
id: 83865853-59aa-449e-9600-74b9d89a6d6e
status: test
description: Detect attacker collecting audio via SoundRecorder application.
author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.md
  - https://eqllib.readthedocs.io/en/latest/analytics/f72a98cb-7b3d-4100-99c3-a138b6e9ff6e.html
date: 2019/10/24
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\SoundRecorder.exe'
    CommandLine|contains: '/FILE'
  condition: selection
falsepositives:
  - Legitimate audio capture by legitimate user.
level: medium
tags:
  - attack.collection
  - attack.t1123

```
