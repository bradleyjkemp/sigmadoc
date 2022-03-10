---
title: "Psr.exe Capture Screenshots"
aliases:
  - "/rule/2158f96f-43c2-43cb-952a-ab4580f32382"


tags:
  - attack.collection
  - attack.t1113



status: test





date: Tue, 22 Oct 2019 06:06:07 +0200


---

The psr.exe captures desktop screenshots and saves them on the local machine

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Psr.yml
* https://www.sans.org/summit-archives/file/summit-archive-1493861893.pdf
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_psr_capture_screenshots.yml))
```yaml
title: Psr.exe Capture Screenshots
id: 2158f96f-43c2-43cb-952a-ab4580f32382
status: test
description: The psr.exe captures desktop screenshots and saves them on the local machine
author: Beyu Denis, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Psr.yml
  - https://www.sans.org/summit-archives/file/summit-archive-1493861893.pdf
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md
date: 2019/10/12
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\Psr.exe'
    CommandLine|contains: '/start'
  condition: selection
falsepositives:
  - Unknown
level: medium
tags:
  - attack.collection
  - attack.t1113

```
