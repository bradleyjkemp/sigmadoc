---
title: "Microsoft Office Add-In Loading"
aliases:
  - "/rule/8e1cb247-6cf6-42fa-b440-3f27d57e9936"


tags:
  - attack.persistence
  - attack.t1137.006



status: test





date: Wed, 1 Jul 2020 10:58:39 +0200


---

Detects add-ins that load when Microsoft Word or Excel starts (.wll/.xll are simply .dll fit for Word or Excel).

<!--more-->


## Known false-positives

* Legitimate add-ins



## References

* Internal Research


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_office_persistence.yml))
```yaml
title: Microsoft Office Add-In Loading
id: 8e1cb247-6cf6-42fa-b440-3f27d57e9936
status: test
description: Detects add-ins that load when Microsoft Word or Excel starts (.wll/.xll are simply .dll fit for Word or Excel).
author: NVISO
references:
  - Internal Research
date: 2020/05/11
modified: 2021/11/27
logsource:
  category: file_event
  product: windows
detection:
  wlldropped:
    TargetFilename|contains: \Microsoft\Word\Startup\
    TargetFilename|endswith: .wll
  xlldropped:
    TargetFilename|contains: \Microsoft\Excel\Startup\
    TargetFilename|endswith: .xll
  generic:
    TargetFilename|contains: \Microsoft\Addins\
    TargetFilename|endswith:
      - .xlam
      - .xla
  condition: (wlldropped or xlldropped or generic)
falsepositives:
  - Legitimate add-ins
level: high
tags:
  - attack.persistence
  - attack.t1137.006

```
