---
title: "Data Compressed - rar.exe"
aliases:
  - "/rule/6f3e2987-db24-4c78-a860-b4f4095a7095"
ruleid: 6f3e2987-db24-4c78-a860-b4f4095a7095

tags:
  - attack.collection
  - attack.t1560.001



status: test





date: Tue, 22 Oct 2019 14:00:52 +0300


---

An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.

<!--more-->


## Known false-positives

* Highly likely if rar is a default archiver in the monitored environment.



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md
* https://eqllib.readthedocs.io/en/latest/analytics/1ec33c93-3d0b-4a28-8014-dbdaae5c60ae.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_data_compressed_with_rar.yml))
```yaml
title: Data Compressed - rar.exe
id: 6f3e2987-db24-4c78-a860-b4f4095a7095
status: test
description: An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.
author: Timur Zinniatullin, E.M. Anhaus, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md
  - https://eqllib.readthedocs.io/en/latest/analytics/1ec33c93-3d0b-4a28-8014-dbdaae5c60ae.html
date: 2019/10/21
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rar.exe'
    CommandLine|contains: ' a '
  condition: selection
fields:
  - Image
  - CommandLine
  - User
  - LogonGuid
  - Hashes
  - ParentProcessGuid
  - ParentCommandLine
falsepositives:
  - Highly likely if rar is a default archiver in the monitored environment.
level: low
tags:
  - attack.collection
  - attack.t1560.001

```
