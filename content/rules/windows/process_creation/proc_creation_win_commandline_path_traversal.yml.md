---
title: "Cmd.exe CommandLine Path Traversal"
aliases:
  - "/rule/087790e3-3287-436c-bccf-cbd0184a7db1"


tags:
  - attack.execution
  - attack.t1059.003



status: test





date: Thu, 11 Jun 2020 15:48:48 +0200


---

detects the usage of path traversal in cmd.exe indicating possible command/argument confusion/hijacking

<!--more-->


## Known false-positives

* (not much) some benign Java tools may product false-positive commandlines for loading libraries



## References

* https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/
* https://twitter.com/Oddvarmoe/status/1270633613449723905


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_commandline_path_traversal.yml))
```yaml
title: Cmd.exe CommandLine Path Traversal
id: 087790e3-3287-436c-bccf-cbd0184a7db1
status: test
description: detects the usage of path traversal in cmd.exe indicating possible command/argument confusion/hijacking
author: xknow @xknow_infosec
references:
  - https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/
  - https://twitter.com/Oddvarmoe/status/1270633613449723905
date: 2020/06/11
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentCommandLine|contains|all:
      - 'cmd'
      - '/c'
    CommandLine|contains: '/../../'
  condition: selection
falsepositives:
  - (not much) some benign Java tools may product false-positive commandlines for loading libraries
level: high
tags:
  - attack.execution
  - attack.t1059.003

```
