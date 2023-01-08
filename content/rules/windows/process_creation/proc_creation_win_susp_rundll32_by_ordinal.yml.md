---
title: "Suspicious Call by Ordinal"
aliases:
  - "/rule/e79a9e79-eb72-4e78-a628-0e7e8f59e89c"
ruleid: e79a9e79-eb72-4e78-a628-0e7e8f59e89c

tags:
  - attack.defense_evasion
  - attack.t1218.011



status: stable





date: Tue, 22 Oct 2019 12:40:26 +0200


---

Detects suspicious calls of DLLs in rundll32.dll exports by ordinal

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment
* Windows control panel elements have been identified as source (mmc)



## References

* https://techtalk.pcmatic.com/2017/11/30/running-dll-files-malware-analysis/
* https://github.com/Neo23x0/DLLRunner
* https://twitter.com/cyb3rops/status/1186631731543236608
* https://www.welivesecurity.com/2022/03/01/isaacwiper-hermeticwizard-wiper-worm-targeting-ukraine/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_rundll32_by_ordinal.yml))
```yaml
title: Suspicious Call by Ordinal
id: e79a9e79-eb72-4e78-a628-0e7e8f59e89c
description: Detects suspicious calls of DLLs in rundll32.dll exports by ordinal
status: stable
references:
    - https://techtalk.pcmatic.com/2017/11/30/running-dll-files-malware-analysis/
    - https://github.com/Neo23x0/DLLRunner
    - https://twitter.com/cyb3rops/status/1186631731543236608
    - https://www.welivesecurity.com/2022/03/01/isaacwiper-hermeticwizard-wiper-worm-targeting-ukraine/
tags:
    - attack.defense_evasion
    - attack.t1218.011
author: Florian Roth
date: 2019/10/22
modified: 2022/03/08
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains:
            - ',#'
            - ', #'
            - '.dll #'  # Sysmon removes , in its log
            - '.ocx #'  # HermeticWizard
    filter:
        CommandLine|contains|all:
            - 'EDGEHTML.dll'
            - '#141'
    condition: selection and not filter
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
    - Windows control panel elements have been identified as source (mmc)
level: high

```
