---
title: "CACTUSTORCH Remote Thread Creation"
aliases:
  - "/rule/2e4e488a-6164-4811-9ea1-f960c7359c40"

tags:
  - attack.defense_evasion
  - attack.t1093
  - attack.t1055.012
  - attack.execution
  - attack.t1064
  - attack.t1059.005
  - attack.t1059.007
  - attack.t1218.005



date: Fri, 1 Feb 2019 23:27:53 +0100


---

Detects remote thread creation from CACTUSTORCH as described in references.

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/SBousseaden/status/1090588499517079552
* https://github.com/mdsecactivebreach/CACTUSTORCH


## Raw rule
```yaml
title: CACTUSTORCH Remote Thread Creation
id: 2e4e488a-6164-4811-9ea1-f960c7359c40
description: Detects remote thread creation from CACTUSTORCH as described in references.
references:
    - https://twitter.com/SBousseaden/status/1090588499517079552
    - https://github.com/mdsecactivebreach/CACTUSTORCH
status: experimental
author: '@SBousseaden (detection), Thomas Patzke (rule)'
date: 2019/02/01
modified: 2020/08/28
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        SourceImage:
            - '*\System32\cscript.exe'
            - '*\System32\wscript.exe'
            - '*\System32\mshta.exe'
            - '*\winword.exe'
            - '*\excel.exe'
        TargetImage: '*\SysWOW64\\*'
        StartModule: null
    condition: selection
tags:
    - attack.defense_evasion
    - attack.t1093          # an old one
    - attack.t1055.012
    - attack.execution
    - attack.t1064          # an old one
    - attack.t1059.005
    - attack.t1059.007
    - attack.t1218.005
falsepositives:
    - unknown
level: high

```
