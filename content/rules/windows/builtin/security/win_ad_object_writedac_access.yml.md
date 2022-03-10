---
title: "AD Object WriteDAC Access"
aliases:
  - "/rule/028c7842-4243-41cd-be6f-12f3cf1a26c7"


tags:
  - attack.defense_evasion
  - attack.t1222.001



status: test





date: Thu, 24 Oct 2019 14:34:16 +0200


---

Detects WRITE_DAC access to a domain object

<!--more-->


## Known false-positives

* Unknown



## References

* https://threathunterplaybook.com/notebooks/windows/05_defense_evasion/WIN-190101151110.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_ad_object_writedac_access.yml))
```yaml
title: AD Object WriteDAC Access
id: 028c7842-4243-41cd-be6f-12f3cf1a26c7
status: test
description: Detects WRITE_DAC access to a domain object
author: Roberto Rodriguez @Cyb3rWard0g
references:
  - https://threathunterplaybook.com/notebooks/windows/05_defense_evasion/WIN-190101151110.html
date: 2019/09/12
modified: 2021/11/27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    ObjectServer: 'DS'
    AccessMask: '0x40000'
    ObjectType:
      - '19195a5b-6da0-11d0-afd3-00c04fd930c9'
      - 'domainDNS'
  condition: selection
falsepositives:
  - Unknown
level: critical
tags:
  - attack.defense_evasion
  - attack.t1222.001

```
