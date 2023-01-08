---
title: "Pingback Backdoor"
aliases:
  - "/rule/35a7dc42-bc6f-46e0-9f83-81f8e56c8d4b"
ruleid: 35a7dc42-bc6f-46e0-9f83-81f8e56c8d4b

tags:
  - attack.persistence
  - attack.t1574.001



status: experimental





date: Wed, 5 May 2021 12:37:50 +0545


---

Detects the use of Pingback backdoor that creates ICMP tunnel for C2 as described in the trustwave report

<!--more-->


## Known false-positives

* Very unlikely



## References

* https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/backdoor-at-the-end-of-the-icmp-tunnel
* https://app.any.run/tasks/4a54c651-b70b-4b72-84d7-f34d301d6406


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_pingback_backdoor.yml))
```yaml
title: Pingback Backdoor
id: 35a7dc42-bc6f-46e0-9f83-81f8e56c8d4b
status: experimental
description: Detects the use of Pingback backdoor that creates ICMP tunnel for C2 as described in the trustwave report
author: Bhabesh Raj
date: 2021/05/05
modified: 2021/09/09
references:
    - https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/backdoor-at-the-end-of-the-icmp-tunnel
    - https://app.any.run/tasks/4a54c651-b70b-4b72-84d7-f34d301d6406
tags:
    - attack.persistence
    - attack.t1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Image|endswith: 'msdtc.exe'
        ImageLoaded: 'C:\Windows\oci.dll'
    condition: selection
falsepositives:
    - Very unlikely
level: high
```
