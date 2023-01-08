---
title: "RedMimicry Winnti Playbook Registry Manipulation"
aliases:
  - "/rule/5b175490-b652-4b02-b1de-5b5b4083c5f8"
ruleid: 5b175490-b652-4b02-b1de-5b5b4083c5f8

tags:
  - attack.defense_evasion
  - attack.t1112



status: test





date: Wed, 1 Jul 2020 09:17:31 +0200


---

Detects actions caused by the RedMimicry Winnti playbook

<!--more-->


## Known false-positives

* Unknown



## References

* https://redmimicry.com


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_redmimicry_winnti_reg.yml))
```yaml
title: RedMimicry Winnti Playbook Registry Manipulation
id: 5b175490-b652-4b02-b1de-5b5b4083c5f8
status: test
description: Detects actions caused by the RedMimicry Winnti playbook
author: Alexander Rausch
references:
  - https://redmimicry.com
date: 2020/06/24
modified: 2021/11/27
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
tags:
  - attack.defense_evasion
  - attack.t1112

```
