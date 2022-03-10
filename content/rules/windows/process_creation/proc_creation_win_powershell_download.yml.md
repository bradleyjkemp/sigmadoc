---
title: "PowerShell Download from URL"
aliases:
  - "/rule/3b6ab547-8ec2-4991-b9d2-2b06702a48d7"


tags:
  - attack.execution
  - attack.t1059.001



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a Powershell process that contains download commands in its command line string

<!--more-->


## Known false-positives

* unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_powershell_download.yml))
```yaml
title: PowerShell Download from URL
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: test
description: Detects a Powershell process that contains download commands in its command line string
author: Florian Roth, oscd.community, Jonhnathan Ribeiro
date: 2019/01/16
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - 'new-object'
      - 'net.webclient).'
      - 'download'
    CommandLine|contains:
      - 'string('
      - 'file('
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - unknown
level: medium
tags:
  - attack.execution
  - attack.t1059.001

```
