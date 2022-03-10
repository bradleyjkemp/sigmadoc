---
title: "Cobalt Strike DNS Beaconing"
aliases:
  - "/rule/2975af79-28c4-4d2f-a951-9095f229df29"


tags:
  - attack.command_and_control
  - attack.t1071.004



status: experimental





date: Thu, 10 May 2018 14:08:05 +0200


---

Detects suspicious DNS queries known from Cobalt Strike beacons

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.icebrg.io/blog/footprints-of-fin7-tracking-actor-patterns
* https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/net_mal_dns_cobaltstrike.yml))
```yaml
title: Cobalt Strike DNS Beaconing
id: 2975af79-28c4-4d2f-a951-9095f229df29
status: experimental
description: Detects suspicious DNS queries known from Cobalt Strike beacons
author: Florian Roth
date: 2018/05/10
modified: 2021/03/24
references:
    - https://www.icebrg.io/blog/footprints-of-fin7-tracking-actor-patterns
    - https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/
logsource:
    category: dns
detection:
    selection1:
        query|startswith:
            - 'aaa.stage.' 
            - 'post.1'
    selection2:
        query|contains: '.stage.123456.'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: critical
tags:
    - attack.command_and_control
    - attack.t1071.004

```
