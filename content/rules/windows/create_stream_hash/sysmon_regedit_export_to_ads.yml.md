---
title: "Exports Registry Key To an Alternate Data Stream"
aliases:
  - "/rule/0d7a9363-af70-4e7b-a3b7-1a176b7fbe84"
ruleid: 0d7a9363-af70-4e7b-a3b7-1a176b7fbe84

tags:
  - attack.defense_evasion
  - attack.t1564.004



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Exports the target Registry key and hides it in the specified alternate data stream.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Regedit.yml
* https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/create_stream_hash/sysmon_regedit_export_to_ads.yml))
```yaml
title: Exports Registry Key To an Alternate Data Stream
id: 0d7a9363-af70-4e7b-a3b7-1a176b7fbe84
status: test
description: Exports the target Registry key and hides it in the specified alternate data stream.
author: Oddvar Moe, Sander Wiebing, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Regedit.yml
  - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
date: 2020/10/07
modified: 2021/11/27
logsource:
  product: windows
  category: create_stream_hash
detection:
  selection:
    Image|endswith: '\regedit.exe'
  condition: selection
fields:
  - TargetFilename
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1564.004

```
