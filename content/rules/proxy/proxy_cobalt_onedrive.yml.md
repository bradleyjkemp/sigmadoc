---
title: "CobaltStrike Malleable OneDrive Browsing Traffic Profile"
aliases:
  - "/rule/c9b33401-cc6a-4cf6-83bb-57ddcb2407fc"
ruleid: c9b33401-cc6a-4cf6-83bb-57ddcb2407fc

tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001



status: test





date: Mon, 19 Nov 2018 17:13:54 +0100


---

Detects Malleable OneDrive Profile

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/onedrive_getonly.profile


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_cobalt_onedrive.yml))
```yaml
title: CobaltStrike Malleable OneDrive Browsing Traffic Profile
id: c9b33401-cc6a-4cf6-83bb-57ddcb2407fc
status: test
description: Detects Malleable OneDrive Profile
author: Markus Neis
references:
  - https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/onedrive_getonly.profile
date: 2019/11/12
modified: 2022/01/07
logsource:
  category: proxy
detection:
  selection:
    cs-method: 'GET'
    c-uri|endswith: '?manifest=wac'
    cs-host: 'onedrive.live.com'
  filter:
    c-uri|startswith: 'http'
    c-uri|contains: '://onedrive.live.com/'
  condition: selection and not filter
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001

```
