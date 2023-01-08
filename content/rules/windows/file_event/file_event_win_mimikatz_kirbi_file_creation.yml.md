---
title: "Mimikatz Kirbi File Creation"
aliases:
  - "/rule/9e099d99-44c2-42b6-a6d8-54c3545cab29"
ruleid: 9e099d99-44c2-42b6-a6d8-54c3545cab29

tags:
  - attack.credential_access
  - attack.t1558



status: test





date: Mon, 8 Nov 2021 11:21:40 +0100


---

Detects the creation of files that contain Kerberos tickets based on an extension used by the popular tool Mimikatz

<!--more-->


## Known false-positives

* Unlikely



## References

* https://cobalt.io/blog/kerberoast-attack-techniques


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_mimikatz_kirbi_file_creation.yml))
```yaml
title: Mimikatz Kirbi File Creation
id: 9e099d99-44c2-42b6-a6d8-54c3545cab29
status: test
description: Detects the creation of files that contain Kerberos tickets based on an extension used by the popular tool Mimikatz
author: Florian Roth
references:
    - https://cobalt.io/blog/kerberoast-attack-techniques
date: 2021/11/08
tags:
    - attack.credential_access
    - attack.t1558
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '.kirbi'
    condition: selection
falsepositives:
    - Unlikely
level: critical

```
