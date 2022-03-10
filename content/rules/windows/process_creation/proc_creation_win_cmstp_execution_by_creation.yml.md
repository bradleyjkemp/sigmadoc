---
title: "CMSTP Execution Process Creation"
aliases:
  - "/rule/7d4cdc5a-0076-40ca-aac8-f7e714570e47"


tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1218.003
  - attack.g0069
  - car.2019-04-001



status: stable





date: Mon, 16 Jul 2018 02:53:41 +0300


---

Detects various indicators of Microsoft Connection Manager Profile Installer execution

<!--more-->


## Known false-positives

* Legitimate CMSTP use (unlikely in modern enterprise environments)



## References

* https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_cmstp_execution_by_creation.yml))
```yaml
title: CMSTP Execution Process Creation
id: 7d4cdc5a-0076-40ca-aac8-f7e714570e47
status: stable
description: Detects various indicators of Microsoft Connection Manager Profile Installer execution
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218.003
    - attack.g0069
    - car.2019-04-001
author: Nik Seetharaman
date: 2018/07/16
modified: 2020/12/23
references:
    - https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
fields:
    - CommandLine
    - ParentCommandLine
    - Details
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high
logsource:
    category: process_creation
    product: windows
detection:
    # CMSTP Spawning Child Process
    selection:
        ParentImage|endswith: '\cmstp.exe'
    condition: selection

```