---
title: "Suspicious WebDav Client Execution"
aliases:
  - "/rule/2dbd9d3d-9e27-42a8-b8df-f13825c6c3d5"


tags:
  - attack.exfiltration
  - attack.t1048.003



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

A General detection for svchost.exe spawning rundll32.exe with command arguments like C:\windows\system32\davclnt.dll,DavSetCookie. This could be an indicator of exfiltration or use of WebDav to launch code (hosted on WebDav Server).

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/OTRF/detection-hackathon-apt29/issues/17
* https://threathunterplaybook.com/evals/apt29/detections/7.B.4_C10730EA-6345-4934-AA0F-B0EFCA0C4BA6.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_webdav_client_execution.yml))
```yaml
title: Suspicious WebDav Client Execution
id: 2dbd9d3d-9e27-42a8-b8df-f13825c6c3d5
status: test
description: A General detection for svchost.exe spawning rundll32.exe with command arguments like C:\windows\system32\davclnt.dll,DavSetCookie. This could be an indicator of exfiltration or use of WebDav to launch code (hosted on WebDav Server).
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
references:
  - https://github.com/OTRF/detection-hackathon-apt29/issues/17
  - https://threathunterplaybook.com/evals/apt29/detections/7.B.4_C10730EA-6345-4934-AA0F-B0EFCA0C4BA6.html
date: 2020/05/02
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains: 'C:\windows\system32\davclnt.dll,DavSetCookie'
  condition: selection
falsepositives:
  - unknown
level: medium
tags:
  - attack.exfiltration
  - attack.t1048.003

```