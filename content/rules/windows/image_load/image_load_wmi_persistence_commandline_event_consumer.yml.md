---
title: "WMI Persistence - Command Line Event Consumer"
aliases:
  - "/rule/05936ce2-ee05-4dae-9d03-9a391cf2d2c6"


tags:
  - attack.t1546.003
  - attack.persistence



status: test





date: Wed, 7 Mar 2018 23:05:10 +0100


---

Detects WMI command line event consumers

<!--more-->


## Known false-positives

* Unknown (data set is too small; further testing needed)



## References

* https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_wmi_persistence_commandline_event_consumer.yml))
```yaml
title: WMI Persistence - Command Line Event Consumer
id: 05936ce2-ee05-4dae-9d03-9a391cf2d2c6
status: test
description: Detects WMI command line event consumers
author: Thomas Patzke
references:
  - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
date: 2018/03/07
modified: 2021/11/27
logsource:
  category: image_load
  product: windows
detection:
  selection:
    Image: 'C:\Windows\System32\wbem\WmiPrvSE.exe'
    ImageLoaded|endswith: '\wbemcons.dll'
  condition: selection
falsepositives:
  - Unknown (data set is too small; further testing needed)
level: high
tags:
  - attack.t1546.003
  - attack.persistence

```
