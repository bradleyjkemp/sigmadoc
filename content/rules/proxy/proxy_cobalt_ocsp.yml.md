---
title: "CobaltStrike Malleable (OCSP) Profile"
aliases:
  - "/rule/37325383-740a-403d-b1a2-b2b4ab7992e7"
ruleid: 37325383-740a-403d-b1a2-b2b4ab7992e7

tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001



status: test





date: Mon, 19 Nov 2018 17:22:32 +0100


---

Detects Malleable (OCSP) Profile with Typo (OSCP) in URL

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/ocsp.profile


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_cobalt_ocsp.yml))
```yaml
title: CobaltStrike Malleable (OCSP) Profile
id: 37325383-740a-403d-b1a2-b2b4ab7992e7
status: test
description: Detects Malleable (OCSP) Profile with Typo (OSCP) in URL
author: Markus Neis
references:
  - https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/ocsp.profile
date: 2019/11/12
modified: 2021/11/27
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains: '/oscp/'
    cs-host: 'ocsp.verisign.com'

  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001

```
