---
title: "DIT Snapshot Viewer Use"
aliases:
  - "/rule/d3b70aad-097e-409c-9df2-450f80dc476b"
ruleid: d3b70aad-097e-409c-9df2-450f80dc476b

tags:
  - attack.credential_access
  - attack.t1003.003



status: test





date: Sat, 4 Jul 2020 23:21:52 +0300


---

Detects the use of Ditsnap tool. Seems to be a tool for ransomware groups.

<!--more-->


## Known false-positives

* Legitimate admin usage



## References

* https://thedfirreport.com/2020/06/21/snatch-ransomware/
* https://github.com/yosqueoy/ditsnap


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_ditsnap.yml))
```yaml
title: DIT Snapshot Viewer Use
id: d3b70aad-097e-409c-9df2-450f80dc476b
status: test
description: Detects the use of Ditsnap tool. Seems to be a tool for ransomware groups.
author: 'Furkan Caliskan (@caliskanfurkan_)'
references:
  - https://thedfirreport.com/2020/06/21/snatch-ransomware/
  - https://github.com/yosqueoy/ditsnap
date: 2020/07/04
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\ditsnap.exe'
  selection2:
    CommandLine|contains:
      - 'ditsnap.exe'
  condition: selection or selection2
falsepositives:
  - Legitimate admin usage
level: high
tags:
  - attack.credential_access
  - attack.t1003.003

```
