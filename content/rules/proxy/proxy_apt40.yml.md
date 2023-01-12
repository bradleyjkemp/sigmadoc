---
title: "APT40 Dropbox Tool User Agent"
aliases:
  - "/rule/5ba715b6-71b7-44fd-8245-f66893e81b3d"
ruleid: 5ba715b6-71b7-44fd-8245-f66893e81b3d

tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.exfiltration
  - attack.t1567.002



status: test





date: Fri, 7 Jun 2019 14:03:41 +0200


---

Detects suspicious user agent string of APT40 Dropbox tool

<!--more-->


## Known false-positives

* Old browsers



## References

* Internal research from Florian Roth


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_apt40.yml))
```yaml
title: APT40 Dropbox Tool User Agent
id: 5ba715b6-71b7-44fd-8245-f66893e81b3d
status: test
description: Detects suspicious user agent string of APT40 Dropbox tool
author: Thomas Patzke
references:
  - Internal research from Florian Roth
date: 2019/11/12
modified: 2021/11/27
logsource:
  category: proxy
detection:
  selection:
    c-useragent: 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36'
    r-dns: 'api.dropbox.com'
  condition: selection
fields:
  - c-ip
  - c-uri
falsepositives:
  - Old browsers
level: high
tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.exfiltration
  - attack.t1567.002

```