---
title: "Narrator's Feedback-Hub Persistence"
aliases:
  - "/rule/f663a6d9-9d1b-49b8-b2b1-0637914d199a"
ruleid: f663a6d9-9d1b-49b8-b2b1-0637914d199a

tags:
  - attack.persistence
  - attack.t1547.001



status: test





date: Fri, 25 Oct 2019 17:57:56 +0300


---

Detects abusing Windows 10 Narrator's Feedback-Hub

<!--more-->


## Known false-positives

* unknown



## References

* https://giuliocomi.blogspot.com/2019/10/abusing-windows-10-narrators-feedback.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_narrator_feedback_persistance.yml))
```yaml
title: Narrator's Feedback-Hub Persistence
id: f663a6d9-9d1b-49b8-b2b1-0637914d199a
status: test
description: Detects abusing Windows 10 Narrator's Feedback-Hub
author: Dmitriy Lifanov, oscd.community
references:
  - https://giuliocomi.blogspot.com/2019/10/abusing-windows-10-narrators-feedback.html
date: 2019/10/25
modified: 2021/11/27
logsource:
  category: registry_event
  product: windows
detection:
  selection1:
    EventType: DeleteValue
    TargetObject|endswith: '\AppXypsaf9f1qserqevf0sws76dx4k9a5206\Shell\open\command\DelegateExecute'
  selection2:
    TargetObject|endswith: '\AppXypsaf9f1qserqevf0sws76dx4k9a5206\Shell\open\command\(Default)'
  condition: 1 of selection*
falsepositives:
  - unknown
level: high
tags:
  - attack.persistence
  - attack.t1547.001

```
