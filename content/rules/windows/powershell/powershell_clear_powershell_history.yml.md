---
title: "Clear PowerShell History"
aliases:
  - "/rule/dfba4ce1-e0ea-495f-986e-97140f31af2d"

tags:
  - attack.defense_evasion
  - attack.t1070.003
  - attack.t1146



status: experimental



level: medium



date: Tue, 29 Oct 2019 03:44:22 +0300


---

Detects keywords that could indicate clearing PowerShell history

<!--more-->


## Known false-positives

* some PS-scripts



## References

* https://gist.github.com/hook-s3c/7363a856c3cdbadeb71085147f042c1a


## Raw rule
```yaml
title: Clear PowerShell History
id: dfba4ce1-e0ea-495f-986e-97140f31af2d
status: experimental
description: Detects keywords that could indicate clearing PowerShell history
date: 2019/10/25
author: Ilyas Ochkov, oscd.community
references:
    - https://gist.github.com/hook-s3c/7363a856c3cdbadeb71085147f042c1a
tags:
    - attack.defense_evasion
    - attack.t1070.003
    - attack.t1146  # an old one
logsource:
    product: windows
    service: powershell
detection:
    keywords:
        - 'del (Get-PSReadlineOption).HistorySavePath'
        - 'Set-PSReadlineOption –HistorySaveStyle SaveNothing'
        - 'Remove-Item (Get-PSReadlineOption).HistorySavePath'
        - 'rm (Get-PSReadlineOption).HistorySavePath'
    condition: keywords
falsepositives:
    - some PS-scripts
level: medium

```
