---
title: "Sysinternals SDelete File Deletion"
aliases:
  - "/rule/6ddab845-b1b8-49c2-bbf7-1a11967f64bc"
ruleid: 6ddab845-b1b8-49c2-bbf7-1a11967f64bc

tags:
  - attack.defense_evasion
  - attack.t1070.004



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

A General detection to trigger for the deletion of files by Sysinternals SDelete. It looks for the common name pattern used to rename files.

<!--more-->


## Known false-positives

* Legitime usage of SDelete



## References

* https://github.com/OTRF/detection-hackathon-apt29/issues/9
* https://threathunterplaybook.com/evals/apt29/detections/4.B.4_83D62033-105A-4A02-8B75-DAB52D8D51EC.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_delete/file_delete_win_sysinternals_sdelete_file_deletion.yml))
```yaml
title: Sysinternals SDelete File Deletion
id: 6ddab845-b1b8-49c2-bbf7-1a11967f64bc
status: test
description: A General detection to trigger for the deletion of files by Sysinternals SDelete. It looks for the common name pattern used to rename files.
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
references:
  - https://github.com/OTRF/detection-hackathon-apt29/issues/9
  - https://threathunterplaybook.com/evals/apt29/detections/4.B.4_83D62033-105A-4A02-8B75-DAB52D8D51EC.html
date: 2020/05/02
modified: 2021/11/27
logsource:
  product: windows
  category: file_delete
detection:
  selection:
    TargetFilename|endswith:
      - '.AAA'
      - '.ZZZ'
  condition: selection
falsepositives:
  - Legitime usage of SDelete
level: medium
tags:
  - attack.defense_evasion
  - attack.t1070.004

```