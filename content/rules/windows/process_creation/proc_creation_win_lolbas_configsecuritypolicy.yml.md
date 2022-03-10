---
title: "Suspicious ConfigSecurityPolicy Execution"
aliases:
  - "/rule/1f0f6176-6482-4027-b151-00071af39d7e"


tags:
  - attack.exfiltration
  - attack.t1567



status: experimental





date: Fri, 26 Nov 2021 18:50:19 +0100


---

Upload file, credentials or data exfiltration with Binary part of Windows Defender

<!--more-->


## Known false-positives

* unknown



## References

* https://lolbas-project.github.io/lolbas/Binaries/ConfigSecurityPolicy/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbas_configsecuritypolicy.yml))
```yaml
title: Suspicious ConfigSecurityPolicy Execution
id: 1f0f6176-6482-4027-b151-00071af39d7e
status: experimental
description: Upload file, credentials or data exfiltration with Binary part of Windows Defender
references:
    - https://lolbas-project.github.io/lolbas/Binaries/ConfigSecurityPolicy/
tags:
    - attack.exfiltration
    - attack.t1567
author: frack113
date: 2021/11/26
logsource:
    category: process_creation
    product: windows
detection:
    lolbas:
        CommandLine|contains: ConfigSecurityPolicy.exe
    remote:
        CommandLine|contains:
            - 'https://'
            - 'http://'
            - 'ftp://'
    condition: lolbas and remote
falsepositives:
    - unknown
level: medium

```
