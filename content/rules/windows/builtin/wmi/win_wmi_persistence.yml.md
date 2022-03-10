---
title: "WMI Persistence"
aliases:
  - "/rule/0b7889b4-5577-4521-a60a-3376ee7f9f7b"


tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1546.003



status: experimental





date: Tue, 22 Aug 2017 10:02:54 +0200


---

Detects suspicious WMI event filter and command line event consumer based on WMI and Security Logs.

<!--more-->


## Known false-positives

* Unknown (data set is too small; further testing needed)



## References

* https://twitter.com/mattifestation/status/899646620148539397
* https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/wmi/win_wmi_persistence.yml))
```yaml
title: WMI Persistence
id: 0b7889b4-5577-4521-a60a-3376ee7f9f7b
status: experimental
description: Detects suspicious WMI event filter and command line event consumer based on WMI and Security Logs.
author: Florian Roth, Gleb Sukhodolskiy, Timur Zinniatullin oscd.community
date: 2017/08/22
modified: 2022/02/10
references:
    - https://twitter.com/mattifestation/status/899646620148539397
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1546.003
logsource:
    product: windows
    service: wmi #native windows detection
    definition: 'WMI Namespaces Auditing and SACL should be configured, EventID 5861 and 5859 detection requires Windows 10, 2012 and higher'
detection:
    wmi_filter_to_consumer_binding:
        EventID: 5861
    consumer_keywords:
        - 'ActiveScriptEventConsumer'
        - 'CommandLineEventConsumer'
        - 'CommandLineTemplate'
        # - 'Binding EventFilter'  # too many false positive with HP Health Driver
    wmi_filter_registration:
        EventID: 5859
    filter_scmevent:
        Provider: 'SCM Event Provider'
        Query: 'select * from MSFT_SCMEventLogEvent'
        User: 'S-1-5-32-544'
        PossibleCause: 'Permanent'
    condition: ( (wmi_filter_to_consumer_binding and consumer_keywords) or (wmi_filter_registration) ) and not filter_scmevent
falsepositives:
    - Unknown (data set is too small; further testing needed)
level: medium
```