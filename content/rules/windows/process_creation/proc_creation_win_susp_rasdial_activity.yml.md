---
title: "Suspicious RASdial Activity"
aliases:
  - "/rule/6bba49bf-7f8c-47d6-a1bb-6b4dece4640e"
ruleid: 6bba49bf-7f8c-47d6-a1bb-6b4dece4640e

tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1059



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious process related to rasdial.exe

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment



## References

* https://twitter.com/subTee/status/891298217907830785


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_rasdial_activity.yml))
```yaml
title: Suspicious RASdial Activity
id: 6bba49bf-7f8c-47d6-a1bb-6b4dece4640e
status: test
description: Detects suspicious process related to rasdial.exe
author: juju4
references:
  - https://twitter.com/subTee/status/891298217907830785
date: 2019/01/16
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - rasdial.exe
  condition: selection
falsepositives:
  - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1059

```
