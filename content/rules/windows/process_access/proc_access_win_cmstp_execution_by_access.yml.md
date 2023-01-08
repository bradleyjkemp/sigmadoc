---
title: "CMSTP Execution Process Access"
aliases:
  - "/rule/3b4b232a-af90-427c-a22f-30b0c0837b95"
ruleid: 3b4b232a-af90-427c-a22f-30b0c0837b95

tags:
  - attack.defense_evasion
  - attack.t1218.003
  - attack.execution
  - attack.t1559.001
  - attack.g0069
  - attack.g0080
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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_cmstp_execution_by_access.yml))
```yaml
title: CMSTP Execution Process Access
id: 3b4b232a-af90-427c-a22f-30b0c0837b95
status: stable
description: Detects various indicators of Microsoft Connection Manager Profile Installer execution
tags:
    - attack.defense_evasion
    - attack.t1218.003
    - attack.execution
    - attack.t1559.001
    - attack.g0069
    - attack.g0080
    - car.2019-04-001
author: Nik Seetharaman
date: 2018/07/16
modified: 2021/06/27
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
    product: windows
    category: process_access
detection:
    # Process Access Call Trace
    selection:
        CallTrace|contains: 'cmlua.dll'
    condition: selection

```
