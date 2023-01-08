---
title: "Suspicious MSExchangeMailboxReplication ASPX Write"
aliases:
  - "/rule/7280c9f3-a5af-45d0-916a-bc01cb4151c9"
ruleid: 7280c9f3-a5af-45d0-916a-bc01cb4151c9

tags:
  - attack.initial_access
  - attack.t1190
  - attack.persistence
  - attack.t1505.003



status: experimental





date: Fri, 25 Feb 2022 16:02:42 +0100


---

Detects suspicious activity in which the MSExchangeMailboxReplication process writes .asp and .apsx files to disk, which could be a sign of ProxyShell exploitation

<!--more-->


## Known false-positives

* Unknown



## References

* https://redcanary.com/blog/blackbyte-ransomware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_susp_exchange_aspx_write.yml))
```yaml
title: Suspicious MSExchangeMailboxReplication ASPX Write
id: 7280c9f3-a5af-45d0-916a-bc01cb4151c9
status: experimental
description: Detects suspicious activity in which the MSExchangeMailboxReplication process writes .asp and .apsx files to disk, which could be a sign of ProxyShell exploitation
references:
    - https://redcanary.com/blog/blackbyte-ransomware/
author: Florian Roth
date: 2022/02/25
tags:
    - attack.initial_access
    - attack.t1190
    - attack.persistence
    - attack.t1505.003
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image|endswith: '\MSExchangeMailboxReplication.exe'
        TargetFilename|endswith: 
            - '.aspx'
            - '.asp'
    condition: selection
falsepositives:
    - Unknown
level: high

```
