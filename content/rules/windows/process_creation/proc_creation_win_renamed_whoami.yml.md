---
title: "Renamed Whoami Execution"
aliases:
  - "/rule/f1086bf7-a0c4-4a37-9102-01e573caf4a0"
ruleid: f1086bf7-a0c4-4a37-9102-01e573caf4a0

tags:
  - attack.discovery
  - attack.t1033
  - car.2016-03-001



status: experimental





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects the execution of whoami that has been renamed to a different name to avoid detection

<!--more-->


## Known false-positives

* Unknown



## References

* https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/
* https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_renamed_whoami.yml))
```yaml
title: Renamed Whoami Execution
id: f1086bf7-a0c4-4a37-9102-01e573caf4a0
status: experimental
description: Detects the execution of whoami that has been renamed to a different name to avoid detection
references:
    - https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/
    - https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/
author: Florian Roth
date: 2021/08/12
tags:
    - attack.discovery
    - attack.t1033
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'whoami.exe'
    filter:
        Image|endswith: '\whoami.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical

```