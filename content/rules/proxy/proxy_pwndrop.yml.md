---
title: "PwnDrp Access"
aliases:
  - "/rule/2b1ee7e4-89b6-4739-b7bb-b811b6607e5e"


tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1102.001
  - attack.t1102.003



status: test





date: Fri, 17 Apr 2020 08:55:40 +0200


---

Detects downloads from PwnDrp web servers developed for red team testing and most likely also used for criminal activity

<!--more-->


## Known false-positives

* Unknown



## References

* https://breakdev.org/pwndrop/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_pwndrop.yml))
```yaml
title: PwnDrp Access
id: 2b1ee7e4-89b6-4739-b7bb-b811b6607e5e
status: test
description: Detects downloads from PwnDrp web servers developed for red team testing and most likely also used for criminal activity
author: Florian Roth
references:
  - https://breakdev.org/pwndrop/
date: 2020/04/15
modified: 2021/11/27
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains: '/pwndrop/'
  condition: selection
fields:
  - ClientIP
  - c-uri
  - c-useragent
falsepositives:
  - Unknown
level: critical
tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1102.001
  - attack.t1102.003

```