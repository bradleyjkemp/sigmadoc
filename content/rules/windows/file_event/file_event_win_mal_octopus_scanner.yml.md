---
title: "Octopus Scanner Malware"
aliases:
  - "/rule/805c55d9-31e6-4846-9878-c34c75054fe9"
ruleid: 805c55d9-31e6-4846-9878-c34c75054fe9

tags:
  - attack.t1195
  - attack.t1195.001



status: test





date: Tue, 9 Jun 2020 16:12:05 +0200


---

Detects Octopus Scanner Malware.

<!--more-->


## Known false-positives

* Unknown



## References

* https://securitylab.github.com/research/octopus-scanner-malware-open-source-supply-chain


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_mal_octopus_scanner.yml))
```yaml
title: Octopus Scanner Malware
id: 805c55d9-31e6-4846-9878-c34c75054fe9
status: test
description: Detects Octopus Scanner Malware.
author: NVISO
references:
  - https://securitylab.github.com/research/octopus-scanner-malware-open-source-supply-chain
date: 2020/06/09
modified: 2021/11/27
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
      - '\AppData\Local\Microsoft\Cache134.dat'
      - '\AppData\Local\Microsoft\ExplorerSync.db'
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.t1195
  - attack.t1195.001

```
