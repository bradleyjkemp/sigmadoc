---
title: "Solarwinds SUPERNOVA Webshell Access"
aliases:
  - "/rule/a2cee20b-eacc-459f-861d-c02e5d12f1db"


tags:
  - attack.persistence
  - attack.t1505.003



status: experimental





date: Thu, 17 Dec 2020 09:05:08 +0100


---

Detects access to SUPERNOVA webshell as described in Guidepoint report

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.guidepointsecurity.com/supernova-solarwinds-net-webshell-analysis/
* https://www.anquanke.com/post/id/226029


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_solarwinds_supernova_webshell.yml))
```yaml
title: Solarwinds SUPERNOVA Webshell Access
id: a2cee20b-eacc-459f-861d-c02e5d12f1db
status: experimental
description: Detects access to SUPERNOVA webshell as described in Guidepoint report
author: Florian Roth
date: 2020/12/17
modified: 2021/08/09
references:
    - https://www.guidepointsecurity.com/supernova-solarwinds-net-webshell-analysis/
    - https://www.anquanke.com/post/id/226029
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    category: webserver
detection:
    selection1:
        c-uri|contains|all:
            - 'logoimagehandler.ashx'
            - 'clazz'
    selection2:
        c-uri|contains: 'logoimagehandler.ashx'
        sc-status: 500
    condition: selection1 or selection2
fields:
    - client_ip
    - response
falsepositives:
    - Unknown
level: critical
```
