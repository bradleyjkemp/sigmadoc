---
title: "Pulse Secure Attack CVE-2019-11510"
aliases:
  - "/rule/2dbc10d7-a797-49a8-8776-49efa6442e60"
ruleid: 2dbc10d7-a797-49a8-8776-49efa6442e60

tags:
  - attack.initial_access
  - attack.t1190



status: test





date: Mon, 18 Nov 2019 15:33:58 +0100


---

Detects CVE-2019-11510 exploitation attempt - URI contains Guacamole

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.exploit-db.com/exploits/47297


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_pulsesecure_cve_2019_11510.yml))
```yaml
title: Pulse Secure Attack CVE-2019-11510
id: 2dbc10d7-a797-49a8-8776-49efa6442e60
status: test
description: Detects CVE-2019-11510 exploitation attempt - URI contains Guacamole
author: Florian Roth
references:
  - https://www.exploit-db.com/exploits/47297
date: 2019/11/18
modified: 2021/11/27
logsource:
  category: webserver
detection:
  selection:
    c-uri: '*?/dana/html5acc/guacamole/*'
  condition: selection
fields:
  - client_ip
  - vhost
  - url
  - response
falsepositives:
  - Unknown
level: critical
tags:
  - attack.initial_access
  - attack.t1190

```
