---
title: "Reconnaissance Activity with Net Command"
aliases:
  - "/rule/2887e914-ce96-435f-8105-593937e90757"

tags:
  - attack.discovery
  - attack.t1087
  - attack.t1082
  - car.2016-03-001



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a set of commands often used in recon stages by different attack groups

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment



## References

* https://twitter.com/haroonmeer/status/939099379834658817
* https://twitter.com/c_APT_ure/status/939475433711722497
* https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html


## Raw rule
```yaml
title: Reconnaissance Activity with Net Command
id: 2887e914-ce96-435f-8105-593937e90757
status: experimental
description: Detects a set of commands often used in recon stages by different attack groups
references:
    - https://twitter.com/haroonmeer/status/939099379834658817
    - https://twitter.com/c_APT_ure/status/939475433711722497
    - https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html
author: Florian Roth, Markus Neis
date: 2018/08/22
modified: 2018/12/11
tags:
    - attack.discovery
    - attack.t1087
    - attack.t1082
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - tasklist
            - net time
            - systeminfo
            - whoami
            - nbtstat
            - net start
            - '*\net1 start'
            - qprocess
            - nslookup
            - hostname.exe
            - '*\net1 user /domain'
            - '*\net1 group /domain'
            - '*\net1 group "domain admins" /domain'
            - '*\net1 group "Exchange Trusted Subsystem" /domain'
            - '*\net1 accounts /domain'
            - '*\net1 user net localgroup administrators'
            - netstat -an
    timeframe: 15s
    condition: selection | count() by CommandLine > 4
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```