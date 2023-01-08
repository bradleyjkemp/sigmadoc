---
title: "Exchange Exploitation CVE-2021-28480"
aliases:
  - "/rule/a2a9d722-0acb-4096-bccc-daaf91a5037b"
ruleid: a2a9d722-0acb-4096-bccc-daaf91a5037b

tags:
  - attack.initial_access
  - attack.t1190



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects successful exploitation of Exchange vulnerability as reported in CVE-2021-28480

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/GossiTheDog/status/1392965209132871683?s=20


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_expl_exchange_cve_2021_28480.yml))
```yaml
title: Exchange Exploitation CVE-2021-28480
id: a2a9d722-0acb-4096-bccc-daaf91a5037b
status: experimental
description: Detects successful exploitation of Exchange vulnerability as reported in CVE-2021-28480
references:
  - https://twitter.com/GossiTheDog/status/1392965209132871683?s=20
author: Florian Roth
date: 2021/05/14
tags:
    - attack.initial_access
    - attack.t1190
logsource:
  category: webserver
detection:
  selection:
    c-uri|contains: '/owa/calendar/a'
    cs-method: 'POST'
  filter:
    sc-status: 503
  condition: selection and not filter
falsepositives:
  - Unknown
level: critical
```
