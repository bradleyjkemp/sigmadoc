---
title: "WMI Persistence - Script Event Consumer File Write"
aliases:
  - "/rule/33f41cdd-35ac-4ba8-814b-c6a4244a1ad4"


tags:
  - attack.t1546.003
  - attack.persistence



status: test





date: Wed, 7 Mar 2018 23:05:10 +0100


---

Detects file writes of WMI script event consumer

<!--more-->


## Known false-positives

* Dell Power Manager (C:\Program Files\Dell\PowerManager\DpmPowerPlanSetup.exe)



## References

* https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_wmi_persistence_script_event_consumer_write.yml))
```yaml
title: WMI Persistence - Script Event Consumer File Write
id: 33f41cdd-35ac-4ba8-814b-c6a4244a1ad4
status: test
description: Detects file writes of WMI script event consumer
author: Thomas Patzke
references:
  - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
date: 2018/03/07
modified: 2021/11/27
logsource:
  product: windows
  category: file_event
detection:
  selection:
    Image: 'C:\WINDOWS\system32\wbem\scrcons.exe'
  condition: selection
falsepositives:
  - Dell Power Manager (C:\Program Files\Dell\PowerManager\DpmPowerPlanSetup.exe)
level: high
tags:
  - attack.t1546.003
  - attack.persistence

```
