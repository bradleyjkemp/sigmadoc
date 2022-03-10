---
title: "Guacamole Two Users Sharing Session Anomaly"
aliases:
  - "/rule/1edd77db-0669-4fef-9598-165bda82826d"


tags:
  - attack.credential_access
  - attack.t1212



status: test





date: Fri, 3 Jul 2020 13:20:03 +0200


---

Detects suspicious session with two users present

<!--more-->


## Known false-positives

* Unknown



## References

* https://research.checkpoint.com/2020/apache-guacamole-rce/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/other/lnx_susp_guacamole.yml))
```yaml
title: Guacamole Two Users Sharing Session Anomaly
id: 1edd77db-0669-4fef-9598-165bda82826d
status: test
description: Detects suspicious session with two users present
author: Florian Roth
references:
  - https://research.checkpoint.com/2020/apache-guacamole-rce/
date: 2020/07/03
modified: 2021/11/27
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
tags:
  - attack.credential_access
  - attack.t1212

```
