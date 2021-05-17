---
title: "Flash Player Update from Suspicious Location"
aliases:
  - "/rule/4922a5dd-6743-4fc2-8e81-144374280997"

tags:
  - attack.initial_access
  - attack.t1189
  - attack.execution
  - attack.t1204.002
  - attack.t1204
  - attack.defense_evasion
  - attack.t1036.005
  - attack.t1036



status: experimental



level: high



date: Wed, 25 Oct 2017 08:40:14 +0200


---

Detects a flashplayer update from an unofficial location

<!--more-->


## Known false-positives

* Unknown flash download locations



## References

* https://gist.github.com/roycewilliams/a723aaf8a6ac3ba4f817847610935cfb


## Raw rule
```yaml
title: Flash Player Update from Suspicious Location
id: 4922a5dd-6743-4fc2-8e81-144374280997
status: experimental
description: Detects a flashplayer update from an unofficial location
author: Florian Roth
date: 2017/10/25
references:
    - https://gist.github.com/roycewilliams/a723aaf8a6ac3ba4f817847610935cfb
logsource:
    category: proxy
detection:
    selection:
        c-uri-query:
            - '*/install_flash_player.exe'
            - '*/flash_install.php*'
    filter:
        c-uri-stem: '*.adobe.com/*'
    condition: selection and not filter
falsepositives:
    - Unknown flash download locations
level: high
tags:
    - attack.initial_access
    - attack.t1189
    - attack.execution
    - attack.t1204.002
    - attack.t1204  # an old one
    - attack.defense_evasion
    - attack.t1036.005
    - attack.t1036  # an old one
```
