---
title: "Accessing WinAPI in PowerShell. Code Injection."
aliases:
  - "/rule/eeb2e3dc-c1f4-40dd-9bd5-149ee465ad50"
ruleid: eeb2e3dc-c1f4-40dd-9bd5-149ee465ad50

tags:
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detecting Code injection with PowerShell in another process

<!--more-->


## Known false-positives

* Unknown



## References

* https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/create_remote_thread/sysmon_powershell_code_injection.yml))
```yaml
title: Accessing WinAPI in PowerShell. Code Injection.
id: eeb2e3dc-c1f4-40dd-9bd5-149ee465ad50
status: test
description: Detecting Code injection with PowerShell in another process
author: Nikita Nazarov, oscd.community
references:
  - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse
date: 2020/10/06
modified: 2021/11/27
logsource:
  product: windows
  category: create_remote_thread
  definition: 'Note that you have to configure logging for CreateRemoteThread in Symson config'
detection:
  selection:
    SourceImage|endswith: '\powershell.exe'
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.execution
  - attack.t1059.001

```
