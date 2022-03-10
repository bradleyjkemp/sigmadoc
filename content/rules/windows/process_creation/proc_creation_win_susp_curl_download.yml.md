---
title: "Suspicious Curl Usage on Windows"
aliases:
  - "/rule/e218595b-bbe7-4ee5-8a96-f32a24ad3468"


tags:
  - attack.command_and_control
  - attack.t1105



status: test





date: Fri, 3 Jul 2020 18:55:44 +0200


---

Detects a suspicious curl process start on Windows and outputs the requested document to a local file

<!--more-->


## Known false-positives

* Scripts created by developers and admins
* Administrative activity



## References

* https://twitter.com/reegun21/status/1222093798009790464


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_curl_download.yml))
```yaml
title: Suspicious Curl Usage on Windows
id: e218595b-bbe7-4ee5-8a96-f32a24ad3468
status: test
description: Detects a suspicious curl process start on Windows and outputs the requested document to a local file
author: Florian Roth
references:
  - https://twitter.com/reegun21/status/1222093798009790464
date: 2020/07/03
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    Image|endswith: '\curl.exe'
  selection2:
    Product: 'The curl executable'
  selection3:
    CommandLine|contains: ' -O '
  condition: ( selection1 or selection2 ) and selection3
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Scripts created by developers and admins
  - Administrative activity
level: medium
tags:
  - attack.command_and_control
  - attack.t1105

```
