---
title: "Suspicious Findstr 385201 Execution"
aliases:
  - "/rule/37db85d1-b089-490a-a59a-c7b6f984f480"
ruleid: 37db85d1-b089-490a-a59a-c7b6f984f480

tags:
  - attack.discovery
  - attack.t1518.001



status: experimental





date: Thu, 16 Dec 2021 10:32:45 +0100


---

Discovery of an installed Sysinternals Sysmon service using driver altitude (even if the name is changed).

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md#atomic-test-5---security-software-discovery---sysmon-service


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_findstr_385201.yml))
```yaml
title: Suspicious Findstr 385201 Execution
id: 37db85d1-b089-490a-a59a-c7b6f984f480
status: experimental
description: Discovery of an installed Sysinternals Sysmon service using driver altitude (even if the name is changed).
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md#atomic-test-5---security-software-discovery---sysmon-service
date: 2021/12/16
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \findstr.exe
        CommandLine|contains: ' 385201'
    condition: selection
falsepositives:
    - Unknown
level: high
tags:
    - attack.discovery
    - attack.t1518.001
```
