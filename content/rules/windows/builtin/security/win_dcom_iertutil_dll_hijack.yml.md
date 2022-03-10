---
title: "T1021 DCOM InternetExplorer.Application Iertutil DLL Hijack"
aliases:
  - "/rule/c39f0c81-7348-4965-ab27-2fde35a1b641"


tags:
  - attack.lateral_movement
  - attack.t1021.002
  - attack.t1021.003



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a threat actor creating a file named `iertutil.dll` in the `C:\Program Files\Internet Explorer\` directory over the network for a DCOM InternetExplorer DLL Hijack scenario.

<!--more-->


## Known false-positives

* Unknown



## References

* https://threathunterplaybook.com/notebooks/windows/08_lateral_movement/WIN-201009183000.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_dcom_iertutil_dll_hijack.yml))
```yaml
title: T1021 DCOM InternetExplorer.Application Iertutil DLL Hijack
id: c39f0c81-7348-4965-ab27-2fde35a1b641
status: test
description: Detects a threat actor creating a file named `iertutil.dll` in the `C:\Program Files\Internet Explorer\` directory over the network for a DCOM InternetExplorer DLL Hijack scenario.
author: Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR)
references:
  - https://threathunterplaybook.com/notebooks/windows/08_lateral_movement/WIN-201009183000.html
date: 2020/10/12
modified: 2021/11/27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    RelativeTargetName|endswith: '\Internet Explorer\iertutil.dll'
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
falsepositives:
  - Unknown
level: critical
tags:
  - attack.lateral_movement
  - attack.t1021.002
  - attack.t1021.003

```
