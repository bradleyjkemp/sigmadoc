---
title: "Nginx Core Dump"
aliases:
  - "/rule/59ec40bb-322e-40ab-808d-84fa690d7e56"
ruleid: 59ec40bb-322e-40ab-808d-84fa690d7e56

tags:
  - attack.impact
  - attack.t1499.004



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a core dump of a crashing Nginx worker process, which could be a signal of a serious problem or exploitation attempts.

<!--more-->


## Known false-positives

* Serious issues with a configuration or plugin



## References

* https://docs.nginx.com/nginx/admin-guide/monitoring/debugging/#enabling-core-dumps
* https://www.x41-dsec.de/lab/advisories/x41-2021-002-nginx-resolver-copy/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_nginx_core_dump.yml))
```yaml
title: Nginx Core Dump
id: 59ec40bb-322e-40ab-808d-84fa690d7e56
description: Detects a core dump of a crashing Nginx worker process, which could be a signal of a serious problem or exploitation attempts.
status: experimental
author: Florian Roth
date: 2021/05/31
references:
    - https://docs.nginx.com/nginx/admin-guide/monitoring/debugging/#enabling-core-dumps
    - https://www.x41-dsec.de/lab/advisories/x41-2021-002-nginx-resolver-copy/
logsource:
    product: apache
detection:
    keywords:
        - 'exited on signal 6 (core dumped)'
    condition: keywords
falsepositives:
    - Serious issues with a configuration or plugin
level: high
tags:
    - attack.impact
    - attack.t1499.004

```
