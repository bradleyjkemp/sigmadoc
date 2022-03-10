---
title: "Dropping Of Password Filter DLL"
aliases:
  - "/rule/b7966f4a-b333-455b-8370-8ca53c229762"


tags:
  - attack.credential_access
  - attack.t1556.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects dropping of dll files in system32 that may be used to retrieve user credentials from LSASS

<!--more-->


## Known false-positives

* unknown



## References

* https://pentestlab.blog/2020/02/10/credential-access-password-filter-dll/
* https://github.com/3gstudent/PasswordFilter/tree/master/PasswordFilter


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_credential_access_via_password_filter.yml))
```yaml
title: Dropping Of Password Filter DLL
id: b7966f4a-b333-455b-8370-8ca53c229762
description: Detects dropping of dll files in system32 that may be used to retrieve user credentials from LSASS
status: experimental
author: Sreeman
date: 2020/10/29
modified: 2021/06/11
references:
    - https://pentestlab.blog/2020/02/10/credential-access-password-filter-dll/
    - https://github.com/3gstudent/PasswordFilter/tree/master/PasswordFilter
tags:
    - attack.credential_access
    - attack.t1556.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmdline:
        CommandLine|contains|all:
            - 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
            - 'scecli\0*'
            - 'reg add'
    condition: selection_cmdline
falsepositives:
    - unknown
level: medium

```
