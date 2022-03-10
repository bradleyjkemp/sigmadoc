---
title: "Pingback Backdoor"
aliases:
  - "/rule/2bd63d53-84d4-4210-80ff-bf0658f1bf78"


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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_pingback_backdoor.yml))
```yaml
title: Pingback Backdoor
id: 2bd63d53-84d4-4210-80ff-bf0658f1bf78
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
    category: file_event
detection:
    selection: 
        Image|endswith: updata.exe
        TargetFilename: 'C:\Windows\oci.dll'
    condition: selection
falsepositives:
    - Very unlikely
level: high
```
