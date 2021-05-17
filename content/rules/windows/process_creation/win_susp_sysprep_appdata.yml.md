---
title: "Sysprep on AppData Folder"
aliases:
  - "/rule/d5b9ae7a-e6fc-405e-80ff-2ff9dcc64e7e"

tags:
  - attack.execution



status: experimental



level: medium



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment



## References

* https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets
* https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b


## Raw rule
```yaml
title: Sysprep on AppData Folder
id: d5b9ae7a-e6fc-405e-80ff-2ff9dcc64e7e
status: experimental
description: Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)
references:
    - https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets
    - https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b
tags:
    - attack.execution
author: Florian Roth
date: 2018/06/22
modified: 2018/12/11
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\sysprep.exe *\AppData\\*'
            - sysprep.exe *\AppData\\*
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```
