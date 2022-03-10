---
title: "Windows Registry Trust Record Modification"
aliases:
  - "/rule/295a59c1-7b79-4b47-a930-df12c15fc9c2"


tags:
  - attack.initial_access
  - attack.t1566.001



status: test





date: Wed, 19 Feb 2020 10:13:44 -0500


---

Alerts on trust record modification within the registry, indicating usage of macros

<!--more-->


## Known false-positives

* Alerts on legitimate macro usage as well, will need to filter as appropriate



## References

* https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/
* http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_trust_record_modification.yml))
```yaml
title: Windows Registry Trust Record Modification
id: 295a59c1-7b79-4b47-a930-df12c15fc9c2
status: test
description: Alerts on trust record modification within the registry, indicating usage of macros
author: Antonlovesdnb
references:
  - https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/
  - http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html
date: 2020/02/19
modified: 2021/11/27
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject|contains: 'TrustRecords'
  condition: selection
falsepositives:
  - Alerts on legitimate macro usage as well, will need to filter as appropriate
level: medium
tags:
  - attack.initial_access
  - attack.t1566.001

```
