---
title: "Windows WebDAV User Agent"
aliases:
  - "/rule/e09aed7a-09e0-4c9a-90dd-f0d52507347e"

tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1043



date: Mon, 13 Mar 2017 13:51:32 +0100


---

Detects WebDav DownloadCradle

<!--more-->


## Known false-positives

* Administrative scripts that download files from the Internet
* Administrative scripts that retrieve certain website contents
* Legitimate WebDAV administration



## References

* https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html


## Raw rule
```yaml
title: Windows WebDAV User Agent
id: e09aed7a-09e0-4c9a-90dd-f0d52507347e
status: experimental
description: Detects WebDav DownloadCradle
author: Florian Roth
date: 2018/04/06
modified: 2020/09/03
references:
    - https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
logsource:
    category: proxy
detection:
    selection:
      c-useragent: 'Microsoft-WebDAV-MiniRedir/*'
      cs-method: 'GET'
    condition: selection
fields:
    - ClientIP
    - c-uri
    - c-useragent
    - cs-method
falsepositives:
    - Administrative scripts that download files from the Internet
    - Administrative scripts that retrieve certain website contents
    - Legitimate WebDAV administration
level: high
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1043  # an old one
```
