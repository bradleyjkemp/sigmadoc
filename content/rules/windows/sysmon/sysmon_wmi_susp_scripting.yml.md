---
title: "Suspicious Scripting in a WMI Consumer"
aliases:
  - "/rule/fe21810c-2a8c-478f-8dd3-5a287fb2a0e0"

tags:
  - attack.t1086
  - attack.execution
  - attack.t1059.005



date: Mon, 15 Apr 2019 08:03:53 +0200


---

Detects suspicious scripting in WMI Event Consumers

<!--more-->


## Known false-positives

* Administrative scripts



## References

* https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/
* https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar#L19


## Raw rule
```yaml
title: Suspicious Scripting in a WMI Consumer
id: fe21810c-2a8c-478f-8dd3-5a287fb2a0e0
status: experimental
description: Detects suspicious scripting in WMI Event Consumers
author: Florian Roth
references:
    - https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/
    - https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar#L19
date: 2019/04/15
tags:
    - attack.t1086          # an old one
    - attack.execution
    - attack.t1059.005
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 20
        Destination:
            - '*new-object system.net.webclient).downloadstring(*'
            - '*new-object system.net.webclient).downloadfile(*'
            - '*new-object net.webclient).downloadstring(*'
            - '*new-object net.webclient).downloadfile(*'
            - '* iex(*'
            - '*WScript.shell*'
            - '* -nop *'
            - '* -noprofile *'
            - '* -decode *'
            - '* -enc *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
level: high

```