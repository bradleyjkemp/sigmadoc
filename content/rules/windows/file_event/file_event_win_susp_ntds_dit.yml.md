---
title: "Suspicious Process Writes Ntds.dit"
aliases:
  - "/rule/11b1ed55-154d-4e82-8ad7-83739298f720"
ruleid: 11b1ed55-154d-4e82-8ad7-83739298f720

tags:
  - attack.credential_access
  - attack.t1003.002
  - attack.t1003.003



status: experimental





date: Wed, 12 Jan 2022 11:32:12 +0100


---

Detects suspicious processes that write (copy) a Active Directory database (ntds.dit) file

<!--more-->


## Known false-positives

* Unknown



## References

* https://stealthbits.com/blog/extracting-password-hashes-from-the-ntds-dit-file/
* https://adsecurity.org/?p=2398


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_susp_ntds_dit.yml))
```yaml
title: Suspicious Process Writes Ntds.dit
id: 11b1ed55-154d-4e82-8ad7-83739298f720
status: experimental
description: Detects suspicious processes that write (copy) a Active Directory database (ntds.dit) file
references:
    - https://stealthbits.com/blog/extracting-password-hashes-from-the-ntds-dit-file/
    - https://adsecurity.org/?p=2398
author: Florian Roth
date: 2022/01/11
tags:
    - attack.credential_access
    - attack.t1003.002
    - attack.t1003.003
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '\ntds.dit'
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
