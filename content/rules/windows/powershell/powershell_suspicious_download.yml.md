---
title: "Suspicious PowerShell Download"
aliases:
  - "/rule/65531a81-a694-4e31-ae04-f8ba5bc33759"

tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1086



date: Sun, 5 Mar 2017 15:01:51 +0100


---

Detects suspicious PowerShell download command

<!--more-->


## Known false-positives

* PowerShell scripts that download content from the Internet




## Raw rule
```yaml
title: Suspicious PowerShell Download
id: 65531a81-a694-4e31-ae04-f8ba5bc33759
status: experimental
description: Detects suspicious PowerShell download command
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086  #an old one
author: Florian Roth
date: 2017/03/05
logsource:
    product: windows
    service: powershell
detection:
    downloadfile:
        Message|contains|all:
            - 'System.Net.WebClient'
            - '.DownloadFile('
    downloadstring:
        Message|contains|all:
            - 'System.Net.WebClient'
            - '.DownloadString('
    condition: downloadfile or downloadstring
falsepositives:
    - PowerShell scripts that download content from the Internet
level: medium

```