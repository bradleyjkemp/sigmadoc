---
title: "Detect XSS Attempts By Keywords"
aliases:
  - "/rule/65354b83-a2ea-4ea6-8414-3ab38be0d409"
ruleid: 65354b83-a2ea-4ea6-8414-3ab38be0d409



status: experimental





date: Sun, 15 Aug 2021 16:00:14 +0200


---

Detects XSS that use GET requests by keyword searches in URL strings

<!--more-->


## Known false-positives

* Java scripts,CSS Files and PNG files
* User searches in search boxes of the respective website




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/xss_keywords.yml))
```yaml
title: Detect XSS Attempts By Keywords
id: 65354b83-a2ea-4ea6-8414-3ab38be0d409
status: experimental
description: Detects XSS that use GET requests by keyword searches in URL strings
author: Saw Win Naung
date: 2021/08/15
logsource:
  category: webserver
detection:
  keywords:
    - '=cookie'
    - '=script'
    - '=onload'
    - '=onmouseover'
  condition: keywords
fields:
  - client_ip
  - vhost
  - url
  - response
falsepositives:
  - Java scripts,CSS Files and PNG files
  - User searches in search boxes of the respective website
level: high

```
