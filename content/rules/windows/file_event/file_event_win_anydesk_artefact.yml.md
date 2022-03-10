---
title: "Anydesk Temporary Artefact"
aliases:
  - "/rule/0b9ad457-2554-44c1-82c2-d56a99c42377"


tags:
  - attack.command_and_control
  - attack.t1219



status: experimental





date: Sat, 12 Feb 2022 15:53:13 +0100


---

An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land) 


<!--more-->


## Known false-positives

* legitimate use



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md#atomic-test-2---anydesk-files-detected-test-on-windows


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_anydesk_artefact.yml))
```yaml
title: Anydesk Temporary Artefact
id: 0b9ad457-2554-44c1-82c2-d56a99c42377
status: experimental
description: |
  An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
  These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
  Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land) 
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md#atomic-test-2---anydesk-files-detected-test-on-windows
author: frack113
date: 2022/02/11
logsource:
     category: file_event
     product: windows
detection:
    selection:
        TargetFilename|contains:
            - '\AppData\Roaming\AnyDesk\user.conf'
            - '\AppData\Roaming\AnyDesk\system.conf'
        TargetFilename|endswith: '.temp'
    condition: selection
falsepositives:
    - legitimate use
level: medium
tags:
    - attack.command_and_control
    - attack.t1219

```
