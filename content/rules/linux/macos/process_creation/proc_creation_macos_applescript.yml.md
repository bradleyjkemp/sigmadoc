---
title: "MacOS Scripting Interpreter AppleScript"
aliases:
  - "/rule/1bc2e6c5-0885-472b-bed6-be5ea8eace55"
ruleid: 1bc2e6c5-0885-472b-bed6-be5ea8eace55

tags:
  - attack.execution
  - attack.t1059.002



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects execution of AppleScript of the macOS scripting language AppleScript.

<!--more-->


## Known false-positives

* Application installers might contain scripts as part of the installation process.



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.002/T1059.002.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_applescript.yml))
```yaml
title: MacOS Scripting Interpreter AppleScript
id: 1bc2e6c5-0885-472b-bed6-be5ea8eace55
status: test
description: Detects execution of AppleScript of the macOS scripting language AppleScript.
author: Alejandro Ortuno, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.002/T1059.002.md
date: 2020/10/21
modified: 2021/11/27
logsource:
  category: process_creation
  product: macos
detection:
  selection:
    Image|endswith:
      - '/osascript'
    CommandLine|contains|all:
      - '-e'
  condition: selection
falsepositives:
  - Application installers might contain scripts as part of the installation process.
level: medium
tags:
  - attack.execution
  - attack.t1059.002

```
