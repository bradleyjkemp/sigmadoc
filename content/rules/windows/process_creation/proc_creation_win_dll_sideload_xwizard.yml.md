---
title: "Xwizard DLL Sideloading"
aliases:
  - "/rule/193d5ccd-6f59-40c6-b5b0-8e32d5ddd3d1"


tags:
  - attack.defense_evasion
  - attack.t1574.002



status: experimental





date: Mon, 20 Sep 2021 10:37:24 +0200


---

Detects the execution of Xwizard tool from the non-default directory which can be used to sideload a custom xwizards.dll

<!--more-->


## Known false-positives

* Windows installed on non-C drive



## References

* https://lolbas-project.github.io/lolbas/Binaries/Xwizard/
* http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_dll_sideload_xwizard.yml))
```yaml
title: Xwizard DLL Sideloading
id: 193d5ccd-6f59-40c6-b5b0-8e32d5ddd3d1
status: experimental
description: Detects the execution of Xwizard tool from the non-default directory which can be used to sideload a custom xwizards.dll
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Xwizard/
    - http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/
author: Christian Burkard 
date: 2021/09/20
tags:
    - attack.defense_evasion
    - attack.t1574.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\xwizard.exe'
    filter:
        Image|startswith: 'C:\Windows\System32\'
    condition: selection and not filter
falsepositives:
    - Windows installed on non-C drive
level: high

```
