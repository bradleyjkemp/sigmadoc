---
title: "Suspicious PowerShell Download"
aliases:
  - "/rule/65531a81-a694-4e31-ae04-f8ba5bc33759"
ruleid: 65531a81-a694-4e31-ae04-f8ba5bc33759

tags:
  - attack.execution
  - attack.t1059.001



status: deprecated





date: Sun, 5 Mar 2017 15:01:51 +0100


---

Detects suspicious PowerShell download command

<!--more-->


## Known false-positives

* PowerShell scripts that download content from the Internet




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/deprecated/powershell_suspicious_download.yml))
```yaml
title: Suspicious PowerShell Download
id: 65531a81-a694-4e31-ae04-f8ba5bc33759
status: deprecated
description: Detects suspicious PowerShell download command
tags:
    - attack.execution
    - attack.t1059.001
author: Florian Roth
date: 2017/03/05
modified: 2021/09/21
logsource:
    product: windows
    service: powershell
detection:
    webclient:
        - 'System.Net.WebClient'
    download:
        - '.DownloadFile('
        - '.DownloadString('
    condition: webclient and download
falsepositives:
    - PowerShell scripts that download content from the Internet
level: medium
```
