---
title: "Java Class Proxy Download"
aliases:
  - "/rule/53c15703-b04c-42bb-9055-1937ddfb3392"


tags:
  - attack.initial_access



status: experimental





date: Tue, 21 Dec 2021 11:25:08 +0100


---

Detects Java class download in proxy logs, e.g. used in Log4shell exploitation attacks against Log4j.

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.lunasec.io/docs/blog/log4j-zero-day/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_java_class_download.yml))
```yaml
title: Java Class Proxy Download
id: 53c15703-b04c-42bb-9055-1937ddfb3392
status: experimental
description: Detects Java class download in proxy logs, e.g. used in Log4shell exploitation attacks against Log4j.
references:
    - https://www.lunasec.io/docs/blog/log4j-zero-day/
author: Andreas Hunkeler (@Karneades)
date: 2021/12/21
tags:
    - attack.initial_access
logsource:
    category: proxy
detection:
    selection:
        c-uri|endswith: '.class'
    condition: selection
falsepositives:
    - Unknown
level: high

```
