---
title: "GoToAssist Temporary Installation Artefact"
aliases:
  - "/rule/5d756aee-ad3e-4306-ad95-cb1abec48de2"
ruleid: 5d756aee-ad3e-4306-ad95-cb1abec48de2

tags:
  - attack.command_and_control
  - attack.t1219



status: experimental





date: Sun, 13 Feb 2022 11:04:00 +0100


---

An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land) 


<!--more-->


## Known false-positives

* legitimate use



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md#atomic-test-4---gotoassist-files-detected-test-on-windows


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_gotoopener_artefact.yml))
```yaml
title: GoToAssist Temporary Installation Artefact
id: 5d756aee-ad3e-4306-ad95-cb1abec48de2
status: experimental
description: |
  An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
  These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
  Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land) 
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md#atomic-test-4---gotoassist-files-detected-test-on-windows
author: frack113
date: 2022/02/13
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\AppData\Local\Temp\LogMeInInc\GoToAssist Remote Support Expert\'
    condition: selection
falsepositives:
    - legitimate use
level: medium
tags:
    - attack.command_and_control
    - attack.t1219

```
