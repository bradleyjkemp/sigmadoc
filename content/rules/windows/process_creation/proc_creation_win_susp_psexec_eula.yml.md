---
title: "Psexec Accepteula Condition"
aliases:
  - "/rule/730fc21b-eaff-474b-ad23-90fd265d4988"


tags:
  - attack.execution
  - attack.t1569
  - attack.t1021



status: test





date: Fri, 30 Oct 2020 13:15:11 +0530


---

Detect ed user accept agreement execution in psexec commandline

<!--more-->


## Known false-positives

* Administrative scripts.




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_psexec_eula.yml))
```yaml
title: Psexec Accepteula Condition
id: 730fc21b-eaff-474b-ad23-90fd265d4988
status: test
description: Detect ed user accept agreement execution in psexec commandline
author: omkar72 - https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
date: 2020/10/30
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\psexec.exe'
    CommandLine|contains: 'accepteula'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
falsepositives:
  - Administrative scripts.
level: medium
tags:
  - attack.execution
  - attack.t1569
  - attack.t1021

```
