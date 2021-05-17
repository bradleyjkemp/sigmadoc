---
title: "Guacamole Two Users Sharing Session Anomaly"
aliases:
  - "/rule/1edd77db-0669-4fef-9598-165bda82826d"



status: experimental



level: high



date: Fri, 3 Jul 2020 13:20:03 +0200


---

Detects suspicious session with two users present

<!--more-->


## Known false-positives

* Unknown



## References

* https://research.checkpoint.com/2020/apache-guacamole-rce/


## Raw rule
```yaml
title: Guacamole Two Users Sharing Session Anomaly
id: 1edd77db-0669-4fef-9598-165bda82826d
status: experimental
description: Detects suspicious session with two users present
author: Florian Roth
date: 2020/07/03
references:
    - https://research.checkpoint.com/2020/apache-guacamole-rce/
logsource:
    product: linux
    service: guacamole
detection:
    selection:
        - '(2 users now present)'
    condition: selection
falsepositives:
    - Unknown
level: high


```
