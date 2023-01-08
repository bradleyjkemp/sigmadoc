---
title: "Uninstall Sysinternals Sysmon"
aliases:
  - "/rule/6a5f68d1-c4b5-46b9-94ee-5324892ea939"
ruleid: 6a5f68d1-c4b5-46b9-94ee-5324892ea939

tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Wed, 12 Jan 2022 20:27:56 +0100


---

Detects the uninstallation of Sysinternals Sysmon, which could be the result of legitimate administration or a manipulation for defense evasion

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md#atomic-test-11---uninstall-sysmon


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uninstall_sysmon.yml))
```yaml
title: Uninstall Sysinternals Sysmon 
id: 6a5f68d1-c4b5-46b9-94ee-5324892ea939
status: experimental
description: Detects the uninstallation of Sysinternals Sysmon, which could be the result of legitimate administration or a manipulation for defense evasion
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md#atomic-test-11---uninstall-sysmon
author: frack113
date: 2022/01/12
logsource:
    category: process_creation
    product: windows
detection:
    sysmon:
        Image|endswith: 
            - \Sysmon64.exe
            - \Sysmon.exe
        CommandLine|contains: '-u'
    condition: sysmon
falsepositives:
    - unknown
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.001

```
