---
title: "Atera Agent Installation"
aliases:
  - "/rule/87261fb2-69d0-42fe-b9de-88c6b5f65a43"
ruleid: 87261fb2-69d0-42fe-b9de-88c6b5f65a43

tags:
  - attack.t1219



status: experimental





date: Wed, 1 Sep 2021 15:24:47 +0545


---

Detects successful installation of Atera Remote Monitoring & Management (RMM) agent as recently found to be used by Conti operators

<!--more-->


## Known false-positives

* Legitimate Atera agent installation



## References

* https://www.advintel.io/post/secret-backdoor-behind-conti-ransomware-operation-introducing-atera-agent


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/application/win_software_atera_rmm_agent_install.yml))
```yaml
title: Atera Agent Installation
id: 87261fb2-69d0-42fe-b9de-88c6b5f65a43
status: experimental
description: Detects successful installation of Atera Remote Monitoring & Management (RMM) agent as recently found to be used by Conti operators
references: 
  - https://www.advintel.io/post/secret-backdoor-behind-conti-ransomware-operation-introducing-atera-agent
date: 2021/09/01
modified: 2021/10/13
author: Bhabesh Raj
level: high
logsource:                     
    service: application  
    product: windows 
tags:
    - attack.t1219
detection:
    selection:
        EventID: 1033
        Provider_Name: MsiInstaller
        Message|contains: AteraAgent
    condition: selection
falsepositives:
    - Legitimate Atera agent installation

```
