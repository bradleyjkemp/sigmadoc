---
title: "Curl Start Combination"
aliases:
  - "/rule/21dd6d38-2b18-4453-9404-a0fe4a0cc288"

tags:
  - attack.execution
  - attack.t1218
  - attack.command_and_control
  - attack.t1105



status: experimental



level: medium



date: Thu, 30 Jan 2020 11:29:01 +0800


---

Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later.

<!--more-->


## Known false-positives

* Administrative scripts (installers)



## References

* https://medium.com/@reegun/curl-exe-is-the-new-rundll32-exe-lolbin-3f79c5f35983


## Raw rule
```yaml
title: Curl Start Combination
id: 21dd6d38-2b18-4453-9404-a0fe4a0cc288
status: experimental
description: Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later.
references: 
    - https://medium.com/@reegun/curl-exe-is-the-new-rundll32-exe-lolbin-3f79c5f35983
author: Sreeman
date: 2020/01/13
modified: 2020/09/05
tags:
    - attack.execution
    - attack.t1218
    - attack.command_and_control
    - attack.t1105    
logsource:
   category: process_creation
   product: windows
detection:
  condition: selection
  selection:
      CommandLine|contains: 'curl* start '
falsepositives:
    - Administrative scripts (installers)
fields:
    - ParentImage
    - CommandLine
level: medium

```
