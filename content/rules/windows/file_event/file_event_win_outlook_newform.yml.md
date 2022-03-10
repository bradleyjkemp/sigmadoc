---
title: "Outlook Form Installation"
aliases:
  - "/rule/c3edc6a5-d9d4-48d8-930e-aab518390917"


tags:
  - attack.persistence
  - attack.t1137.003



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the creation of new Outlook form which can contain malicious code

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/blueteamsec1/status/1401290874202382336?s=20


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_outlook_newform.yml))
```yaml
title: Outlook Form Installation
id: c3edc6a5-d9d4-48d8-930e-aab518390917
status: experimental
description: Detects the creation of new Outlook form which can contain malicious code
references:
    - https://twitter.com/blueteamsec1/status/1401290874202382336?s=20
tags:
    - attack.persistence
    - attack.t1137.003
author: Tobias Michalski
date: 2021/06/10
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image: '\outlook.exe'
        TargetFilename|contains: '\appdata\local\microsoft\FORMS\'
    condition: selection
fields:
    - TargetFilename
falsepositives:
    - unknown
level: high

```
