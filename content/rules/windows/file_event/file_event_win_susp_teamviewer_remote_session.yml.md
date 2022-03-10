---
title: "TeamViewer Remote Session"
aliases:
  - "/rule/162ab1e4-6874-4564-853c-53ec3ab8be01"


tags:
  - attack.command_and_control
  - attack.t1219



status: experimental





date: Sun, 30 Jan 2022 22:26:13 +0100


---

Detects the creation of log files during a TeamViewer remote session

<!--more-->


## Known false-positives

* Legitimate uses of TeamViewer in an organisation



## References

* https://www.teamviewer.com/en-us/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_susp_teamviewer_remote_session.yml))
```yaml
title: TeamViewer Remote Session
id: 162ab1e4-6874-4564-853c-53ec3ab8be01
status: experimental
description: Detects the creation of log files during a TeamViewer remote session
references:
    - https://www.teamviewer.com/en-us/
author: Florian Roth
date: 2022/01/30
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection1:
        TargetFilename|endswith: 
            - '\TeamViewer\RemotePrinting\tvprint.db'
            - '\TeamViewer\TVNetwork.log'
    selection2:
        TargetFilename|contains|all: 
            - '\TeamViewer'
            - '_Logfile.log'
    condition: 1 of selection*
falsepositives:
    - Legitimate uses of TeamViewer in an organisation
level: medium

```
