---
title: "Suspicious Driver Load from Temp"
aliases:
  - "/rule/2c4523d5-d481-4ed0-8ec3-7fbf0cb41a75"
ruleid: 2c4523d5-d481-4ed0-8ec3-7fbf0cb41a75

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1543.003



status: test





date: Sun, 12 Feb 2017 15:50:39 +0100


---

Detects a driver load from a temporary directory

<!--more-->


## Known false-positives

* there is a relevant set of false positives depending on applications in the environment




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/driver_load/driver_load_susp_temp_use.yml))
```yaml
title: Suspicious Driver Load from Temp
id: 2c4523d5-d481-4ed0-8ec3-7fbf0cb41a75
status: test
description: Detects a driver load from a temporary directory
author: Florian Roth
date: 2017/02/12
modified: 2021/11/27
logsource:
  category: driver_load
  product: windows
detection:
  selection:
    ImageLoaded|contains: '\Temp\'
  condition: selection
falsepositives:
  - there is a relevant set of false positives depending on applications in the environment
level: high
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1543.003

```