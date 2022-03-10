---
title: "WMI Event Subscription"
aliases:
  - "/rule/0f06a3a5-6a09-413f-8743-e6cf35561297"


tags:
  - attack.persistence
  - attack.t1546.003



status: test





date: Sat, 12 Jan 2019 12:02:26 +0100


---

Detects creation of WMI event subscription persistence method

<!--more-->


## Known false-positives

* exclude legitimate (vetted) use of WMI event subscription in your network




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/wmi_event/sysmon_wmi_event_subscription.yml))
```yaml
title: WMI Event Subscription
id: 0f06a3a5-6a09-413f-8743-e6cf35561297
status: test
description: Detects creation of WMI event subscription persistence method
author: Tom Ueltschi (@c_APT_ure)
date: 2019/01/12
modified: 2021/11/27
logsource:
  product: windows
  category: wmi_event
detection:
  selector:
    EventID:
      - 19
      - 20
      - 21
  condition: selector
falsepositives:
  - exclude legitimate (vetted) use of WMI event subscription in your network
level: high
tags:
  - attack.persistence
  - attack.t1546.003

```