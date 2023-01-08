---
title: "CACTUSTORCH Remote Thread Creation"
aliases:
  - "/rule/2e4e488a-6164-4811-9ea1-f960c7359c40"
ruleid: 2e4e488a-6164-4811-9ea1-f960c7359c40

tags:
  - attack.defense_evasion
  - attack.t1055.012
  - attack.execution
  - attack.t1059.005
  - attack.t1059.007
  - attack.t1218.005



status: experimental





date: Fri, 1 Feb 2019 23:27:53 +0100


---

Detects remote thread creation from CACTUSTORCH as described in references.

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/SBousseaden/status/1090588499517079552
* https://github.com/mdsecactivebreach/CACTUSTORCH


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/create_remote_thread/sysmon_cactustorch.yml))
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
modified: 2021/11/12
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        SourceImage|endswith:
            - '\System32\cscript.exe'
            - '\System32\wscript.exe'
            - '\System32\mshta.exe'
            - '\winword.exe'
            - '\excel.exe'
        TargetImage|contains: '\SysWOW64\'
        StartModule: null
    condition: selection
tags:
    - attack.defense_evasion
    - attack.t1055.012
    - attack.execution
    - attack.t1059.005
    - attack.t1059.007
    - attack.t1218.005
falsepositives:
    - unknown
level: high

```
