---
title: "Suspicious Double Extension"
aliases:
  - "/rule/1cdd9a09-06c9-4769-99ff-626e2b3991b8"


tags:
  - attack.initial_access
  - attack.t1566.001



status: stable





date: Wed, 26 Jun 2019 15:57:25 +0200


---

Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns

<!--more-->


## Known false-positives

* Unknown



## References

* https://blu3-team.blogspot.com/2019/06/misleading-extensions-xlsexe-docexe.html
* https://twitter.com/blackorbird/status/1140519090961825792


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_double_extension.yml))
```yaml
title: Suspicious Double Extension
id: 1cdd9a09-06c9-4769-99ff-626e2b3991b8
status: stable
description: Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns
author: Florian Roth (rule), @blu3_team (idea)
references:
  - https://blu3-team.blogspot.com/2019/06/misleading-extensions-xlsexe-docexe.html
  - https://twitter.com/blackorbird/status/1140519090961825792
date: 2019/06/26
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '.doc.exe'
      - '.docx.exe'
      - '.xls.exe'
      - '.xlsx.exe'
      - '.ppt.exe'
      - '.pptx.exe'
      - '.rtf.exe'
      - '.pdf.exe'
      - '.txt.exe'
      - '      .exe'
      - '______.exe'
  condition: selection
falsepositives:
  - Unknown
level: critical
tags:
  - attack.initial_access
  - attack.t1566.001

```
