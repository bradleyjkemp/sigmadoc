---
title: "Connection Proxy"
aliases:
  - "/rule/72f4ab3f-787d-495d-a55d-68c2ff46cf4c"

tags:
  - attack.defense_evasion



date: Mon, 13 Jul 2020 01:31:05 +0300


---

Detects setting proxy

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://attack.mitre.org/techniques/T1090/


## Raw rule
```yaml
title: Connection Proxy
id: 72f4ab3f-787d-495d-a55d-68c2ff46cf4c
status: experimental
description: Detects setting proxy
author: Ömer Günal
date: 2020/06/17
references:
    - https://attack.mitre.org/techniques/T1090/
logsource:
    product: linux
detection:
    keyword:
        - 'http_proxy=*'
        - 'https_proxy=*'
    condition: keyword
falsepositives:
    - Legitimate administration activities
level: low
tags:
    - attack.defense_evasion

```
