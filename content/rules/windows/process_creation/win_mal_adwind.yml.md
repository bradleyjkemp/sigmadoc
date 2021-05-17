---
title: "Adwind RAT / JRAT"
aliases:
  - "/rule/1fac1481-2dbc-48b2-9096-753c49b4ec71"

tags:
  - attack.execution
  - attack.t1059.005
  - attack.t1059.007
  - attack.t1064



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects javaw.exe in AppData folder as used by Adwind / JRAT

<!--more-->




## References

* https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100
* https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf


## Raw rule
```yaml
action: global
title: Adwind RAT / JRAT
id: 1fac1481-2dbc-48b2-9096-753c49b4ec71
status: experimental
description: Detects javaw.exe in AppData folder as used by Adwind / JRAT
references:
    - https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100
    - https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf
author: Florian Roth, Tom Ueltschi
date: 2017/11/10
modified: 2020/09/01
tags:
    - attack.execution
    - attack.t1059.005
    - attack.t1059.007
    - attack.t1064  # an old one
detection:
    condition: selection
level: high
---
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\AppData\Roaming\Oracle*\java*.exe *'
            - '*cscript.exe *Retrive*.vbs *'
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename:
            - '*\AppData\Roaming\Oracle\bin\java*.exe'
            - '*\Retrive*.vbs'
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*
        Details: '%AppData%\Roaming\Oracle\bin\\*'

```
