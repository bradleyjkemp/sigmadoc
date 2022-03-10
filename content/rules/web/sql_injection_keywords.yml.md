---
title: "Detect Sql Injection By Keywords"
aliases:
  - "/rule/5513deaf-f49a-46c2-a6c8-3f111b5cb453"




status: test





date: Sun, 15 Aug 2021 16:00:14 +0200


---

Detects sql injection that use GET requests by keyword searches in URL strings

<!--more-->


## Known false-positives

* Java scripts and CSS Files
* User searches in search boxes of the respective website




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/sql_injection_keywords.yml))
```yaml
title: Detect Sql Injection By Keywords
id: 5513deaf-f49a-46c2-a6c8-3f111b5cb453
status: test
description: Detects sql injection that use GET requests by keyword searches in URL strings
author: Saw Win Naung
date: 2020/02/22
modified: 2021/11/27
logsource:
  category: webserver
detection:
  keywords:
    - '=select'
    - '=union'
    - '=concat'
  condition: keywords
fields:
  - client_ip
  - vhost
  - url
  - response
falsepositives:
  - Java scripts and CSS Files
  - User searches in search boxes of the respective website
level: high

```
