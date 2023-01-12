---
title: "iOS Implant URL Pattern"
aliases:
  - "/rule/e06ac91d-b9e6-443d-8e5b-af749e7aa6b6"
ruleid: e06ac91d-b9e6-443d-8e5b-af749e7aa6b6

tags:
  - attack.execution
  - attack.t1203
  - attack.collection
  - attack.t1005
  - attack.t1119
  - attack.credential_access
  - attack.t1528
  - attack.t1552.001



status: test





date: Thu, 31 Jan 2019 12:31:48 +0100


---

Detects URL pattern used by iOS Implant

<!--more-->


## Known false-positives

* Unknown



## References

* https://googleprojectzero.blogspot.com/2019/08/implant-teardown.html
* https://twitter.com/craiu/status/1167358457344925696


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_ios_implant.yml))
```yaml
title: iOS Implant URL Pattern
id: e06ac91d-b9e6-443d-8e5b-af749e7aa6b6
status: test
description: Detects URL pattern used by iOS Implant
author: Florian Roth
references:
  - https://googleprojectzero.blogspot.com/2019/08/implant-teardown.html
  - https://twitter.com/craiu/status/1167358457344925696
date: 2019/08/30
modified: 2021/11/27
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains: '/list/suc?name='
  condition: selection
fields:
  - ClientIP
  - c-uri
  - c-useragent
falsepositives:
  - Unknown
level: critical
tags:
  - attack.execution
  - attack.t1203
  - attack.collection
  - attack.t1005
  - attack.t1119
  - attack.credential_access
  - attack.t1528
  - attack.t1552.001

```