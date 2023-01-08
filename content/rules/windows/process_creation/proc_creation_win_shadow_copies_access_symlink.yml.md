---
title: "Shadow Copies Access via Symlink"
aliases:
  - "/rule/40b19fa6-d835-400c-b301-41f3a2baacaf"
ruleid: 40b19fa6-d835-400c-b301-41f3a2baacaf

tags:
  - attack.credential_access
  - attack.t1003.002
  - attack.t1003.003



status: test





date: Mon, 4 Nov 2019 04:26:34 +0300


---

Shadow Copies storage symbolic link creation using operating systems utilities

<!--more-->


## Known false-positives

* Legitimate administrator working with shadow copies, access for backup purposes



## References

* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_shadow_copies_access_symlink.yml))
```yaml
title: Shadow Copies Access via Symlink
id: 40b19fa6-d835-400c-b301-41f3a2baacaf
status: test
description: Shadow Copies storage symbolic link creation using operating systems utilities
author: Teymur Kheirkhabarov, oscd.community
references:
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
date: 2019/10/22
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - mklink
      - HarddiskVolumeShadowCopy
  condition: selection
falsepositives:
  - Legitimate administrator working with shadow copies, access for backup purposes
level: medium
tags:
  - attack.credential_access
  - attack.t1003.002
  - attack.t1003.003

```
