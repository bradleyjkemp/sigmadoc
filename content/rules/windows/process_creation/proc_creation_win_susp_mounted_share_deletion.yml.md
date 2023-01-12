---
title: "Mounted Share Deleted"
aliases:
  - "/rule/cb7c4a03-2871-43c0-9bbb-18bbdb079896"
ruleid: cb7c4a03-2871-43c0-9bbb-18bbdb079896

tags:
  - attack.defense_evasion
  - attack.t1070.005



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects when when a mounted share is removed. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation

<!--more-->


## Known false-positives

* Administrators or Power users may remove their shares via cmd line



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.005/T1070.005.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_mounted_share_deletion.yml))
```yaml
title: Mounted Share Deleted
id: cb7c4a03-2871-43c0-9bbb-18bbdb079896
status: test
description: Detects when when a mounted share is removed. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation
author: 'oscd.community, @redcanary, Zach Stanford @svch0st'
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.005/T1070.005.md
date: 2020/10/08
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\net.exe'
    Image|endswith: '\net1.exe'
    CommandLine|contains|all:
      - 'share'
      - '/delete'
  condition: selection
falsepositives:
  - Administrators or Power users may remove their shares via cmd line
level: low
tags:
  - attack.defense_evasion
  - attack.t1070.005

```