---
title: "File and Directory Discovery"
aliases:
  - "/rule/d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72"
ruleid: d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72

tags:
  - attack.discovery
  - attack.t1083



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects usage of system utilities to discover files and directories

<!--more-->


## Known false-positives

* Legitimate activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_file_and_directory_discovery.yml))
```yaml
title: File and Directory Discovery
id: d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72
status: test
description: Detects usage of system utilities to discover files and directories
author: Daniil Yugoslavskiy, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md
date: 2020/10/19
modified: 2021/11/27
logsource:
  category: process_creation
  product: linux
detection:
  select_file_with_asterisk:
    Image|endswith: '/file'
    CommandLine|re: '(.){200,}' # execution of the 'file */* *>> /tmp/output.txt' will produce huge commandline
  select_recursive_ls:
    Image|endswith: '/ls'
    CommandLine|contains: '-R'
  select_find_execution:
    Image|endswith: '/find'
  select_tree_execution:
    Image|endswith: '/tree'
  condition: 1 of select*
falsepositives:
  - Legitimate activities
level: informational
tags:
  - attack.discovery
  - attack.t1083

```
