---
title: "Suspicious WMI Execution"
aliases:
  - "/rule/526be59f-a573-4eea-b5f7-f0973207634d"

tags:
  - attack.execution
  - attack.t1047
  - car.2016-03-002



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects WMI executing suspicious commands

<!--more-->


## Known false-positives

* If using Splunk, we recommend | stats count by Computer,CommandLine following for easy hunting by Computer/CommandLine



## References

* https://digital-forensics.sans.org/blog/2010/06/04/wmic-draft/
* https://www.hybrid-analysis.com/sample/4be06ecd234e2110bd615649fe4a6fa95403979acf889d7e45a78985eb50acf9?environmentId=1
* https://blog.malwarebytes.com/threat-analysis/2016/04/rokku-ransomware/


## Raw rule
```yaml
title: Suspicious WMI Execution
id: 526be59f-a573-4eea-b5f7-f0973207634d
status: experimental
description: Detects WMI executing suspicious commands
references:
    - https://digital-forensics.sans.org/blog/2010/06/04/wmic-draft/
    - https://www.hybrid-analysis.com/sample/4be06ecd234e2110bd615649fe4a6fa95403979acf889d7e45a78985eb50acf9?environmentId=1
    - https://blog.malwarebytes.com/threat-analysis/2016/04/rokku-ransomware/
author: Michael Haag, Florian Roth, juju4
date: 2019/01/16
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\wmic.exe'
        CommandLine:
            - '*/NODE:*process call create *'
            - '* path AntiVirusProduct get *'
            - '* path FirewallProduct get *'
            - '* shadowcopy delete *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.execution
    - attack.t1047
    - car.2016-03-002
falsepositives:
    - If using Splunk, we recommend | stats count by Computer,CommandLine following for easy hunting by Computer/CommandLine
level: medium

```