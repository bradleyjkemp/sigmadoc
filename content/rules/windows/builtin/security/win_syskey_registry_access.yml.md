---
title: "SysKey Registry Keys Access"
aliases:
  - "/rule/9a4ff3b8-6187-4fd2-8e8b-e0eae1129495"


tags:
  - attack.discovery
  - attack.t1012



status: test





date: Thu, 24 Oct 2019 02:40:11 +0200


---

Detects handle requests and access operations to specific registry keys to calculate the SysKey

<!--more-->


## Known false-positives

* Unknown



## References

* https://threathunterplaybook.com/notebooks/windows/07_discovery/WIN-190625024610.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_syskey_registry_access.yml))
```yaml
title: SysKey Registry Keys Access
id: 9a4ff3b8-6187-4fd2-8e8b-e0eae1129495
status: test
description: Detects handle requests and access operations to specific registry keys to calculate the SysKey
author: Roberto Rodriguez @Cyb3rWard0g
references:
  - https://threathunterplaybook.com/notebooks/windows/07_discovery/WIN-190625024610.html
date: 2019/08/12
modified: 2021/11/27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4656
      - 4663
    ObjectType: 'key'
    ObjectName|endswith:
      - 'lsa\JD'
      - 'lsa\GBG'
      - 'lsa\Skew1'
      - 'lsa\Data'
  condition: selection
falsepositives:
  - Unknown
level: critical
tags:
  - attack.discovery
  - attack.t1012

```
