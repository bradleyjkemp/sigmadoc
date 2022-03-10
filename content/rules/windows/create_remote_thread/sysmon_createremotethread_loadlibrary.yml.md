---
title: "CreateRemoteThread API and LoadLibrary"
aliases:
  - "/rule/052ec6f6-1adc-41e6-907a-f1c813478bee"


tags:
  - attack.defense_evasion
  - attack.t1055.001



status: test





date: Thu, 24 Oct 2019 14:34:16 +0200


---

Detects potential use of CreateRemoteThread api and LoadLibrary function to inject DLL into a process

<!--more-->


## Known false-positives

* Unknown



## References

* https://threathunterplaybook.com/notebooks/windows/05_defense_evasion/WIN-180719170510.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/create_remote_thread/sysmon_createremotethread_loadlibrary.yml))
```yaml
title: CreateRemoteThread API and LoadLibrary
id: 052ec6f6-1adc-41e6-907a-f1c813478bee
status: test
description: Detects potential use of CreateRemoteThread api and LoadLibrary function to inject DLL into a process
author: Roberto Rodriguez @Cyb3rWard0g
references:
  - https://threathunterplaybook.com/notebooks/windows/05_defense_evasion/WIN-180719170510.html
date: 2019/08/11
modified: 2021/11/27
logsource:
  product: windows
  category: create_remote_thread
detection:
  selection:
    StartModule|endswith: '\kernel32.dll'
    StartFunction: 'LoadLibraryA'
  condition: selection
falsepositives:
  - Unknown
level: critical
tags:
  - attack.defense_evasion
  - attack.t1055.001

```
