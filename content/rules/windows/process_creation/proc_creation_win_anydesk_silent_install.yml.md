---
title: "AnyDesk Silent Installation"
aliases:
  - "/rule/114e7f1c-f137-48c8-8f54-3088c24ce4b9"
ruleid: 114e7f1c-f137-48c8-8f54-3088c24ce4b9

tags:
  - attack.t1219



status: experimental





date: Fri, 6 Aug 2021 14:06:35 +0200


---

AnyDesk Remote Desktop silent installation can be used by attacker to gain remote access.

<!--more-->


## Known false-positives

* Legitimate deployment of AnyDesk



## References

* https://twitter.com/TheDFIRReport/status/1423361119926816776?s=20
* https://support.anydesk.com/Automatic_Deployment


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_anydesk_silent_install.yml))
```yaml
title: AnyDesk Silent Installation
id: 114e7f1c-f137-48c8-8f54-3088c24ce4b9
status: experimental
author: Ján Trenčanský
date: 2021/08/06
description: AnyDesk Remote Desktop silent installation can be used by attacker to gain remote access.
references:
    - https://twitter.com/TheDFIRReport/status/1423361119926816776?s=20
    - https://support.anydesk.com/Automatic_Deployment
tags:
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - '--install'
            - '--start-with-win'
            - '--silent'
    condition: selection
falsepositives:
    - Legitimate deployment of AnyDesk
level: high
fields:
    - CommandLine
    - ParentCommandLine
    - CurrentDirectory

```
