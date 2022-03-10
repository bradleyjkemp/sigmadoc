---
title: "Suspicious Cobalt Strike DNS Beaconing"
aliases:
  - "/rule/f356a9c4-effd-4608-bbf8-408afd5cd006"


tags:
  - attack.command_and_control
  - attack.t1071.004



status: experimental





date: Tue, 9 Nov 2021 17:29:43 +0100


---

Detects a program that invoked suspicious DNS queries known from Cobalt Strike beacons

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.icebrg.io/blog/footprints-of-fin7-tracking-actor-patterns
* https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/dns_query/dns_query_win_mal_cobaltstrike.yml))
```yaml
title: Suspicious Cobalt Strike DNS Beaconing
id: f356a9c4-effd-4608-bbf8-408afd5cd006
status: experimental
description: Detects a program that invoked suspicious DNS queries known from Cobalt Strike beacons
author: Florian Roth
date: 2021/11/09
references:
    - https://www.icebrg.io/blog/footprints-of-fin7-tracking-actor-patterns
    - https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/
tags:
    - attack.command_and_control
    - attack.t1071.004
logsource:
    product: windows
    category: dns_query
detection:
    selection1:
        QueryName|startswith:
            - 'aaa.stage.' 
            - 'post.1'
    selection2:
        QueryName|contains: '.stage.123456.'
    condition: 1 of selection*
fields:
    - Image
    - CommandLine
falsepositives:
    - Unknown
level: critical

```
