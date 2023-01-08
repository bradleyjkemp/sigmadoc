---
title: "DEWMODE Webshell Access"
aliases:
  - "/rule/fdf96c90-42d5-4406-8a9c-14a2c9a016b5"
ruleid: fdf96c90-42d5-4406-8a9c-14a2c9a016b5

tags:
  - attack.persistence
  - attack.t1505.003



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects access to DEWMODE webshell as described in FIREEYE report

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.fireeye.com/blog/threat-research/2021/02/accellion-fta-exploited-for-data-theft-and-extortion.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_unc2546_dewmode_php_webshell.yml))
```yaml
title: DEWMODE Webshell Access
id: fdf96c90-42d5-4406-8a9c-14a2c9a016b5
status: experimental
description: Detects access to DEWMODE webshell as described in FIREEYE report
author: Florian Roth
date: 2021/02/22
references:
    - https://www.fireeye.com/blog/threat-research/2021/02/accellion-fta-exploited-for-data-theft-and-extortion.html
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    category: webserver
detection:
    selection1:
        c-uri|contains|all:
            - '?dwn='
            - '&fn='
            - '.html?'
    selection2:
        c-uri|contains|all:
            - '&dwn='
            - '?fn='
            - '.html?'
    condition: 1 of selection*
fields:
    - client_ip
    - response
falsepositives:
    - Unknown
level: critical
```
