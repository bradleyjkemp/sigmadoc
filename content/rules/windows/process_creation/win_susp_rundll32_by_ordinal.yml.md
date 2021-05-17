---
title: "Suspicious Call by Ordinal"
aliases:
  - "/rule/e79a9e79-eb72-4e78-a628-0e7e8f59e89c"

tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1218.011
  - attack.t1085



status: experimental



level: high



date: Tue, 22 Oct 2019 12:40:26 +0200


---

Detects suspicious calls of DLLs in rundll32.dll exports by ordinal

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment
* Windows contol panel elements have been identified as source (mmc)



## References

* https://techtalk.pcmatic.com/2017/11/30/running-dll-files-malware-analysis/
* https://github.com/Neo23x0/DLLRunner
* https://twitter.com/cyb3rops/status/1186631731543236608


## Raw rule
```yaml
title: Suspicious Call by Ordinal
id: e79a9e79-eb72-4e78-a628-0e7e8f59e89c
description: Detects suspicious calls of DLLs in rundll32.dll exports by ordinal
status: experimental
references:
    - https://techtalk.pcmatic.com/2017/11/30/running-dll-files-malware-analysis/
    - https://github.com/Neo23x0/DLLRunner
    - https://twitter.com/cyb3rops/status/1186631731543236608
tags:
    - attack.defense_evasion
    - attack.execution  # an old one
    - attack.t1218.011
    - attack.t1085      # an old one
author: Florian Roth
date: 2019/10/22
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*\rundll32.exe *,#*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
    - Windows contol panel elements have been identified as source (mmc)
level: high

```
