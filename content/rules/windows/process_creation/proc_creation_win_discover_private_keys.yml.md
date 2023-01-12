---
title: "Discover Private Keys"
aliases:
  - "/rule/213d6a77-3d55-4ce8-ba74-fcfef741974e"
ruleid: 213d6a77-3d55-4ce8-ba74-fcfef741974e

tags:
  - attack.credential_access
  - attack.t1552.004



status: experimental





date: Tue, 20 Jul 2021 11:20:30 +0200


---

Adversaries may search for private key certificate files on compromised systems for insecurely stored credential

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_discover_private_keys.yml))
```yaml
title: Discover Private Keys
id: 213d6a77-3d55-4ce8-ba74-fcfef741974e
status: experimental
author: frack113
date: 2021/07/20
description: Adversaries may search for private key certificate files on compromised systems for insecurely stored credential
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md
tags:
    - attack.credential_access
    - attack.t1552.004
logsource:
    category: process_creation
    product: windows
detection:
    selection_exe:
        CommandLine|contains:
            - 'dir '
            - 'findstr '
    selection_ext:
        CommandLine|contains:
            - '.key'
            - '.pgp'
            - '.gpg'
            - '.ppk'
            - '.p12'
            - '.pem'
            - '.pfx'
            - '.cer'
            - '.p7b'
            - '.asc'
    condition: selection_exe and selection_ext
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium

```