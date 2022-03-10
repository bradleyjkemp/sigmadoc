---
title: "Curl Start Combination"
aliases:
  - "/rule/21dd6d38-2b18-4453-9404-a0fe4a0cc288"


tags:
  - attack.execution
  - attack.t1218
  - attack.command_and_control
  - attack.t1105



status: test





date: Thu, 30 Jan 2020 11:29:01 +0800


---

Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later.

<!--more-->


## Known false-positives

* Administrative scripts (installers)



## References

* https://medium.com/@reegun/curl-exe-is-the-new-rundll32-exe-lolbin-3f79c5f35983


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_curl_start_combo.yml))
```yaml
title: Curl Start Combination
id: 21dd6d38-2b18-4453-9404-a0fe4a0cc288
status: test
description: Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later.
author: Sreeman
references:
  - https://medium.com/@reegun/curl-exe-is-the-new-rundll32-exe-lolbin-3f79c5f35983
date: 2020/01/13
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  condition: selection
  selection:
    CommandLine|contains|all:
      - 'curl'
      - ' start '
fields:
  - ParentImage
  - CommandLine
falsepositives:
  - Administrative scripts (installers)
level: medium
tags:
  - attack.execution
  - attack.t1218
  - attack.command_and_control
  - attack.t1105

```
