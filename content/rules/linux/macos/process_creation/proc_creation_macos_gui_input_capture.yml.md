---
title: "GUI Input Capture - macOS"
aliases:
  - "/rule/60f1ce20-484e-41bd-85f4-ac4afec2c541"
ruleid: 60f1ce20-484e-41bd-85f4-ac4afec2c541

tags:
  - attack.credential_access
  - attack.t1056.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects attempts to use system dialog prompts to capture user credentials

<!--more-->


## Known false-positives

* Legitimate administration tools and activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.002/T1056.002.md
* https://scriptingosx.com/2018/08/user-interaction-from-bash-scripts/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_gui_input_capture.yml))
```yaml
title: GUI Input Capture - macOS
id: 60f1ce20-484e-41bd-85f4-ac4afec2c541
status: experimental
description: Detects attempts to use system dialog prompts to capture user credentials
author: remotephone, oscd.community
date: 2020/10/13
modified: 2021/12/02
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.002/T1056.002.md
    - https://scriptingosx.com/2018/08/user-interaction-from-bash-scripts/
logsource:
    product: macos
    category: process_creation
detection:
    selection1:
        Image:
            - '/usr/sbin/osascript'
    selection2:
        CommandLine|contains|all:
            - '-e'
            - 'display'
            - 'dialog'
            - 'answer'
    selection3:
        CommandLine|contains:
            - 'admin'
            - 'administrator'
            - 'authenticate'
            - 'authentication'
            - 'credentials'
            - 'pass'
            - 'password'
            - 'unlock'
    condition: all of selection*
falsepositives:
    - Legitimate administration tools and activities
level: low
tags:
    - attack.credential_access
    - attack.t1056.002

```
