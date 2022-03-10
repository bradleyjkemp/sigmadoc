---
title: "Empire UserAgent URI Combo"
aliases:
  - "/rule/b923f7d6-ac89-4a50-a71a-89fb846b4aa8"


tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001



status: test





date: Mon, 13 Jul 2020 15:47:53 +0200


---

Detects user agent and URI paths used by empire agents

<!--more-->


## Known false-positives

* Valid requests with this exact user agent to server scripts of the defined names



## References

* https://github.com/BC-SECURITY/Empire


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_empire_ua_uri_combos.yml))
```yaml
title: Empire UserAgent URI Combo
id: b923f7d6-ac89-4a50-a71a-89fb846b4aa8
status: test
description: Detects user agent and URI paths used by empire agents
author: Florian Roth
references:
  - https://github.com/BC-SECURITY/Empire
date: 2020/07/13
modified: 2021/11/27
logsource:
  category: proxy
detection:
  selection:
    c-useragent: 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
    cs-uri-query:
      - '/admin/get.php'
      - '/news.php'
      - '/login/process.php'
    cs-method: 'POST'
  condition: selection
fields:
  - c-uri
  - c-ip
falsepositives:
  - Valid requests with this exact user agent to server scripts of the defined names
level: high
tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001

```
