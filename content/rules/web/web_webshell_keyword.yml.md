---
title: "Webshell Detection by Keyword"
aliases:
  - "/rule/7ff9db12-1b94-4a79-ba68-a2402c5d6729"
ruleid: 7ff9db12-1b94-4a79-ba68-a2402c5d6729

tags:
  - attack.persistence
  - attack.t1505.003



status: test





date: Fri, 10 Feb 2017 19:17:02 +0100


---

Detects webshells that use GET requests by keyword searches in URL strings

<!--more-->


## Known false-positives

* Web sites like wikis with articles on os commands and pages that include the os commands in the URLs
* User searches in search boxes of the respective website




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_webshell_keyword.yml))
```yaml
title: Webshell Detection by Keyword
id: 7ff9db12-1b94-4a79-ba68-a2402c5d6729
status: test
description: Detects webshells that use GET requests by keyword searches in URL strings
author: Florian Roth
date: 2017/02/19
modified: 2021/11/27
logsource:
  category: webserver
detection:
  keywords:
    - =whoami
    - =net%20user
    - =cmd%20/c%20
  condition: keywords
fields:
  - client_ip
  - vhost
  - url
  - response
falsepositives:
  - Web sites like wikis with articles on os commands and pages that include the os commands in the URLs
  - User searches in search boxes of the respective website
level: high
tags:
  - attack.persistence
  - attack.t1505.003

```