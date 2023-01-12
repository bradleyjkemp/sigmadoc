---
title: "NPPSpy Hacktool Usage"
aliases:
  - "/rule/cad1fe90-2406-44dc-bd03-59d0b58fe722"
ruleid: cad1fe90-2406-44dc-bd03-59d0b58fe722

tags:
  - attack.credential_access



status: experimental





date: Mon, 29 Nov 2021 16:03:03 +0100


---

Detects the use of NPPSpy hacktool that stores cleartext passwords of users that logged in to a local file

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md#atomic-test-2---credential-dumping-with-nppspy
* https://twitter.com/0gtweet/status/1465282548494487554


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_hktl_nppspy.yml))
```yaml
title: NPPSpy Hacktool Usage
id: cad1fe90-2406-44dc-bd03-59d0b58fe722
status: experimental
description: Detects the use of NPPSpy hacktool that stores cleartext passwords of users that logged in to a local file
author: Florian Roth
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md#atomic-test-2---credential-dumping-with-nppspy
    - https://twitter.com/0gtweet/status/1465282548494487554
date: 2021/11/29
tags:
    - attack.credential_access
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: 
            - '\NPPSpy.txt'
            - '\NPPSpy.dll'
    condition: selection
falsepositives:
    - Unknown
level: high
```