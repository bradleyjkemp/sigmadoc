---
title: "Multiple Suspicious Resp Codes Caused by Single Client"
aliases:
  - "/rule/6fdfc796-06b3-46e8-af08-58f3505318af"


tags:
  - attack.initial_access
  - attack.t1190



status: test





date: Wed, 11 Jan 2017 00:39:26 +0100


---

Detects possible exploitation activity or bugs in a web application

<!--more-->


## Known false-positives

* Unstable application
* Application that misuses the response codes




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_multiple_suspicious_resp_codes_single_source.yml))
```yaml
title: Multiple Suspicious Resp Codes Caused by Single Client
id: 6fdfc796-06b3-46e8-af08-58f3505318af
status: test
description: Detects possible exploitation activity or bugs in a web application
author: Thomas Patzke
date: 2017/02/19
modified: 2021/11/27
logsource:
  category: webserver
detection:
  selection:
    sc-status:
      - 400
      - 401
      - 403
      - 500
  timeframe: 10m
  condition: selection | count() by clientip > 10
fields:
  - client_ip
  - vhost
  - url
  - response
falsepositives:
  - Unstable application
  - Application that misuses the response codes
level: medium
tags:
  - attack.initial_access
  - attack.t1190

```
