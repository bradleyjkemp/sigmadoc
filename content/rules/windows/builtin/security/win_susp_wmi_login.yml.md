---
title: "Login with WMI"
aliases:
  - "/rule/5af54681-df95-4c26-854f-2565e13cfab0"
ruleid: 5af54681-df95-4c26-854f-2565e13cfab0

tags:
  - attack.execution
  - attack.t1047



status: stable





date: Wed, 4 Dec 2019 11:13:04 +0100


---

Detection of logins performed with WMI

<!--more-->


## Known false-positives

* Monitoring tools
* Legitimate system administration




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_wmi_login.yml))
```yaml
title: Login with WMI
id: 5af54681-df95-4c26-854f-2565e13cfab0
status: stable
description: Detection of logins performed with WMI
author: Thomas Patzke
date: 2019/12/04
tags:
    - attack.execution
    - attack.t1047
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        ProcessName|endswith: '\WmiPrvSE.exe'
    condition: selection
falsepositives:
    - Monitoring tools
    - Legitimate system administration
level: low

```
