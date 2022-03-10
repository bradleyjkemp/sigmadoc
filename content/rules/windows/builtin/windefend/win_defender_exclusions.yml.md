---
title: "Windows Defender Exclusions Added"
aliases:
  - "/rule/1321dc4e-a1fe-481d-a016-52c45f0c8b4f"


tags:
  - attack.defense_evasion
  - attack.t1562.001



status: stable





date: Tue, 13 Jul 2021 13:07:44 +0200


---

Detects the Setting of Windows Defender Exclusions

<!--more-->


## Known false-positives

* Administrator actions



## References

* https://twitter.com/_nullbind/status/1204923340810543109


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/windefend/win_defender_exclusions.yml))
```yaml
title: Windows Defender Exclusions Added
id: 1321dc4e-a1fe-481d-a016-52c45f0c8b4f
description: Detects the Setting of Windows Defender Exclusions
date: 2021/07/06
modified: 2022/02/02
author: Christian Burkard
references:
    - https://twitter.com/_nullbind/status/1204923340810543109
status: stable
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    service: windefend
detection:
    selection1:
        EventID: 5007
        NewValue|contains: '\Microsoft\Windows Defender\Exclusions'
    condition: selection1
falsepositives:
    - Administrator actions
level: medium

```
