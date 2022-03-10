---
title: "Startup Folder File Write"
aliases:
  - "/rule/2aa0a6b4-a865-495b-ab51-c28249537b75"


tags:
  - attack.persistence
  - attack.t1547.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

A General detection for files being created in the Windows startup directory. This could be an indicator of persistence.

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/OTRF/detection-hackathon-apt29/issues/12
* https://threathunterplaybook.com/evals/apt29/detections/5.B.1_611FCA99-97D0-4873-9E51-1C1BA2DBB40D.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_startup_folder_file_write.yml))
```yaml
title: Startup Folder File Write
id: 2aa0a6b4-a865-495b-ab51-c28249537b75
status: test
description: A General detection for files being created in the Windows startup directory. This could be an indicator of persistence.
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
references:
  - https://github.com/OTRF/detection-hackathon-apt29/issues/12
  - https://threathunterplaybook.com/evals/apt29/detections/5.B.1_611FCA99-97D0-4873-9E51-1C1BA2DBB40D.html
date: 2020/05/02
modified: 2021/11/27
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|contains: 'ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
  condition: selection
falsepositives:
  - unknown
level: low
tags:
  - attack.persistence
  - attack.t1547.001

```
