---
title: "CobaltStrike Malleable OneDrive Browsing Traffic Profile"
aliases:
  - "/rule/c9b33401-cc6a-4cf6-83bb-57ddcb2407fc"

tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1043



status: experimental



level: high



date: Mon, 19 Nov 2018 17:13:54 +0100


---

Detects Malleable OneDrive Profile

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/onedrive_getonly.profile


## Raw rule
```yaml
title: CobaltStrike Malleable OneDrive Browsing Traffic Profile
id: c9b33401-cc6a-4cf6-83bb-57ddcb2407fc
status: experimental
description: Detects Malleable OneDrive Profile
author: Markus Neis
date: 2019/11/12
modified: 2020/09/02
references:
    - https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/onedrive_getonly.profile
logsource:
    category: proxy
detection:
    selection:
      cs-method: 'GET'
      c-uri: '*?manifest=wac'
      cs-host: 'onedrive.live.com'
    filter:
      c-uri: 'http*://onedrive.live.com/*'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1043  # an old one
```
