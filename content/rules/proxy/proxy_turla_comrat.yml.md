---
title: "Turla ComRAT"
aliases:
  - "/rule/7857f021-007f-4928-8b2c-7aedbe64bb82"
ruleid: 7857f021-007f-4928-8b2c-7aedbe64bb82

tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001
  - attack.g0010



status: test





date: Fri, 5 Jun 2020 13:18:03 -0400


---

Detects Turla ComRAT patterns

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_turla_comrat.yml))
```yaml
title: Turla ComRAT
id: 7857f021-007f-4928-8b2c-7aedbe64bb82
status: test
description: Detects Turla ComRAT patterns
author: Florian Roth
references:
  - https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf
date: 2020/05/26
modified: 2021/11/27
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains: '/index/index.php?h='
  condition: selection
falsepositives:
  - Unknown
level: critical
tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001
  - attack.g0010

```
