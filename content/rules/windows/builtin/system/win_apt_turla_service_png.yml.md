---
title: "Turla PNG Dropper Service"
aliases:
  - "/rule/1228f8e2-7e79-4dea-b0ad-c91f1d5016c1"


tags:
  - attack.persistence
  - attack.g0010
  - attack.t1543.003



status: test





date: Fri, 23 Nov 2018 08:46:20 +0100


---

This method detects malicious services mentioned in Turla PNG dropper report by NCC Group in November 2018

<!--more-->


## Known false-positives

* unlikely



## References

* https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/november/turla-png-dropper-is-back/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_apt_turla_service_png.yml))
```yaml
title: Turla PNG Dropper Service
id: 1228f8e2-7e79-4dea-b0ad-c91f1d5016c1
status: test
description: This method detects malicious services mentioned in Turla PNG dropper report by NCC Group in November 2018
author: Florian Roth
references:
  - https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/november/turla-png-dropper-is-back/
date: 2018/11/23
modified: 2021/11/30
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
    ServiceName: 'WerFaultSvc'
  condition: selection
falsepositives:
  - unlikely
level: critical
tags:
  - attack.persistence
  - attack.g0010
  - attack.t1543.003

```
