---
title: "Windows Defender AMSI Trigger Detected"
aliases:
  - "/rule/ea9bf0fa-edec-4fb8-8b78-b119f2528186"
ruleid: ea9bf0fa-edec-4fb8-8b78-b119f2528186

tags:
  - attack.execution
  - attack.t1059



status: stable





date: Mon, 14 Sep 2020 18:10:38 +0545


---

Detects triggering of AMSI by Windows Defender.

<!--more-->


## Known false-positives

* unlikely



## References

* https://docs.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/windefend/win_defender_amsi_trigger.yml))
```yaml
title: Windows Defender AMSI Trigger Detected
id: ea9bf0fa-edec-4fb8-8b78-b119f2528186
description: Detects triggering of AMSI by Windows Defender.
date: 2020/09/14
modified: 2021/10/13
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
        Source_Name: 'AMSI'
    condition: selection
falsepositives:
    - unlikely
level: high
tags:
    - attack.execution
    - attack.t1059 

```
