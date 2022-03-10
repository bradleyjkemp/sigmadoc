---
title: "Creation Exe for Service with Unquoted Path"
aliases:
  - "/rule/8c3c76ca-8f8b-4b1d-aaf3-81aebcd367c9"


tags:
  - attack.persistence
  - attack.t1547.009



status: experimental





date: Thu, 30 Dec 2021 11:58:10 +0100


---

Adversaries may execute their own malicious payloads by hijacking vulnerable file path references.
Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch. 


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.009/T1574.009.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_creation_unquoted_service_path.yml))
```yaml
title: Creation Exe for Service with Unquoted Path
id: 8c3c76ca-8f8b-4b1d-aaf3-81aebcd367c9
status: experimental
description: | 
  Adversaries may execute their own malicious payloads by hijacking vulnerable file path references.
  Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch. 
author: frack113
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.009/T1574.009.md
date: 2021/12/30
logsource:
  product: windows
  category: file_event
detection:
  selection:
    # Feel free to add more
    TargetFilename: 'C:\program.exe' 
  condition: selection 
falsepositives:
  - Unknown
level: high
tags:
  - attack.persistence
  - attack.t1547.009
```
