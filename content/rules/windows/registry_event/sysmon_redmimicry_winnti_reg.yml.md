---
title: "RedMimicry Winnti Playbook Registry Manipulation"
aliases:
  - "/rule/5b175490-b652-4b02-b1de-5b5b4083c5f8"

tags:
  - attack.defense_evasion
  - attack.t1112





level: high



date: Wed, 1 Jul 2020 09:17:31 +0200


---

Detects actions caused by the RedMimicry Winnti playbook

<!--more-->


## Known false-positives

* Unknown



## References

* https://redmimicry.com


## Raw rule
```yaml
title: RedMimicry Winnti Playbook Registry Manipulation
id: 5b175490-b652-4b02-b1de-5b5b4083c5f8
description: Detects actions caused by the RedMimicry Winnti playbook
references:
    - https://redmimicry.com
author: Alexander Rausch
date: 2020/06/24
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains: HKLM\SOFTWARE\Microsoft\HTMLHelp\data
    condition: selection
falsepositives:
    - Unknown
level: high

```
