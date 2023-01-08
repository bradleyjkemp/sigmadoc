---
title: "Suspicious PFX File Creation"
aliases:
  - "/rule/dca1b3e8-e043-4ec8-85d7-867f334b5724"
ruleid: dca1b3e8-e043-4ec8-85d7-867f334b5724

tags:
  - attack.credential_access
  - attack.t1552.004



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

A general detection for processes creating PFX files. This could be an indicator of an adversary exporting a local certificate to a PFX file.

<!--more-->


## Known false-positives

* System administrators managing certififcates.



## References

* https://github.com/OTRF/detection-hackathon-apt29/issues/14
* https://threathunterplaybook.com/evals/apt29/detections/6.B.1_6392C9F1-D975-4F75-8A70-433DEDD7F622.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_susp_pfx_file_creation.yml))
```yaml
title: Suspicious PFX File Creation
id: dca1b3e8-e043-4ec8-85d7-867f334b5724
status: test
description: A general detection for processes creating PFX files. This could be an indicator of an adversary exporting a local certificate to a PFX file.
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
references:
  - https://github.com/OTRF/detection-hackathon-apt29/issues/14
  - https://threathunterplaybook.com/evals/apt29/detections/6.B.1_6392C9F1-D975-4F75-8A70-433DEDD7F622.html
date: 2020/05/02
modified: 2021/11/27
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith: '.pfx'
  condition: selection
falsepositives:
  - System administrators managing certififcates.
level: medium
tags:
  - attack.credential_access
  - attack.t1552.004

```
