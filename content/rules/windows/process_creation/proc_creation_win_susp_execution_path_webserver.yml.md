---
title: "Execution in Webserver Root Folder"
aliases:
  - "/rule/35efb964-e6a5-47ad-bbcd-19661854018d"
ruleid: 35efb964-e6a5-47ad-bbcd-19661854018d

tags:
  - attack.persistence
  - attack.t1505.003



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a suspicious program execution in a web service root folder (filter out false positives)

<!--more-->


## Known false-positives

* Various applications
* Tools that include ping or nslookup command invocations




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_execution_path_webserver.yml))
```yaml
title: Execution in Webserver Root Folder
id: 35efb964-e6a5-47ad-bbcd-19661854018d
status: test
description: Detects a suspicious program execution in a web service root folder (filter out false positives)
author: Florian Roth
date: 2019/01/16
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|contains:
      - '\wwwroot\'
      - '\wmpub\'
      - '\htdocs\'
  filter:
    Image|contains:
      - 'bin\'
      - '\Tools\'
      - '\SMSComponent\'
    ParentImage|endswith:
      - '\services.exe'
  condition: selection and not filter
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Various applications
  - Tools that include ping or nslookup command invocations
level: medium
tags:
  - attack.persistence
  - attack.t1505.003

```
