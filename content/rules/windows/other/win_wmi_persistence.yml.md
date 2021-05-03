---
title: "WMI Persistence"
aliases:
  - "/rule/0b7889b4-5577-4521-a60a-3376ee7f9f7b"

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1084
  - attack.t1546.003



date: Tue, 22 Aug 2017 10:02:54 +0200


---

Detects suspicious WMI event filter and command line event consumer based on event id 5861 and 5859 (Windows 10, 2012 and higher)

<!--more-->


## Known false-positives

* Unknown (data set is too small; further testing needed)



## References

* https://twitter.com/mattifestation/status/899646620148539397
* https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/


## Raw rule
```yaml
title: WMI Persistence
id: 0b7889b4-5577-4521-a60a-3376ee7f9f7b
status: experimental
description: Detects suspicious WMI event filter and command line event consumer based on event id 5861 and 5859 (Windows 10, 2012 and higher)
author: Florian Roth
date: 2017/08/22
modified: 2020/08/23
references:
    - https://twitter.com/mattifestation/status/899646620148539397
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1084           # an old one
    - attack.t1546.003
logsource:
    product: windows
    service: wmi
detection:
    selection:
        EventID: 5861
    keywords:
        Message:
            - '*ActiveScriptEventConsumer*'
            - '*CommandLineEventConsumer*'
            - '*CommandLineTemplate*'
        # - 'Binding EventFilter'  # too many false positive with HP Health Driver
    selection2:
        EventID: 5859
    condition: selection and 1 of keywords or selection2
falsepositives:
    - Unknown (data set is too small; further testing needed)
level: medium

```