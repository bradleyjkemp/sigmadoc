---
title: "Findstr GPP Passwords"
aliases:
  - "/rule/91a2c315-9ee6-4052-a853-6f6a8238f90d"
ruleid: 91a2c315-9ee6-4052-a853-6f6a8238f90d

tags:
  - attack.credential_access
  - attack.t1552.006



status: experimental





date: Mon, 27 Dec 2021 20:25:01 +0100


---

Look for the encrypted cpassword value within Group Policy Preference files on the Domain Controller. This value can be decrypted with gpp-decrypt.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.006/T1552.006.md#atomic-test-1---gpp-passwords-findstr


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_findstr_gpp_passwords.yml))
```yaml
title: Findstr GPP Passwords
id: 91a2c315-9ee6-4052-a853-6f6a8238f90d
status: experimental
description: Look for the encrypted cpassword value within Group Policy Preference files on the Domain Controller. This value can be decrypted with gpp-decrypt.
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.006/T1552.006.md#atomic-test-1---gpp-passwords-findstr
date: 2021/12/27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \findstr.exe
        CommandLine|contains|all:
            - cpassword 
            - \sysvol\
            - .xml
    condition: selection
falsepositives:
    - Unknown
level: high
tags:
    - attack.credential_access 
    - attack.t1552.006
```
