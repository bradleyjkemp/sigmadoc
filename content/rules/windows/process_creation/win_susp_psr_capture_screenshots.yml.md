---
title: "Psr.exe Capture Screenshots"
aliases:
  - "/rule/2158f96f-43c2-43cb-952a-ab4580f32382"

tags:
  - attack.collection
  - attack.t1113



date: Tue, 22 Oct 2019 06:06:07 +0200


---

The psr.exe captures desktop screenshots and saves them on the local machine

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Psr.yml
* https://www.sans.org/summit-archives/file/summit-archive-1493861893.pdf


## Raw rule
```yaml
title: Psr.exe Capture Screenshots
id: 2158f96f-43c2-43cb-952a-ab4580f32382
status: experimental
description: The psr.exe captures desktop screenshots and saves them on the local machine
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Psr.yml
    - https://www.sans.org/summit-archives/file/summit-archive-1493861893.pdf
author: Beyu Denis, oscd.community
date: 2019/10/12
modified: 2020/08/28
tags:
    - attack.collection
    - attack.t1113
level: medium
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

```