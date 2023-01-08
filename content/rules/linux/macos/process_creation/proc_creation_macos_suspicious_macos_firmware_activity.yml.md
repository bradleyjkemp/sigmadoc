---
title: "Suspicious MacOS Firmware Activity"
aliases:
  - "/rule/7ed2c9f7-c59d-4c82-a7e2-f859aa676099"
ruleid: 7ed2c9f7-c59d-4c82-a7e2-f859aa676099

tags:
  - attack.impact



status: experimental





date: Thu, 30 Sep 2021 18:47:15 -0500


---

Detects when a user manipulates with Firmward Password on MacOS. NOTE - this command has been disabled on silicon-based apple computers.

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/usnistgov/macos_security/blob/932a51f3e819dd3e02ebfcf3ef433cfffafbe28b/rules/os/os_firmware_password_require.yaml
* https://www.manpagez.com/man/8/firmwarepasswd/
* https://support.apple.com/guide/security/firmware-password-protection-sec28382c9ca/web


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_suspicious_macos_firmware_activity.yml))
```yaml
title: Suspicious MacOS Firmware Activity
id: 7ed2c9f7-c59d-4c82-a7e2-f859aa676099
status: experimental
description: Detects when a user manipulates with Firmward Password on MacOS. NOTE - this command has been disabled on silicon-based apple computers.
author: Austin Songer @austinsonger
date: 2021/09/30
references:
    - https://github.com/usnistgov/macos_security/blob/932a51f3e819dd3e02ebfcf3ef433cfffafbe28b/rules/os/os_firmware_password_require.yaml
    - https://www.manpagez.com/man/8/firmwarepasswd/
    - https://support.apple.com/guide/security/firmware-password-protection-sec28382c9ca/web
logsource:
    category: process_creation
    product: macos
detection:
    selection1:
        Image: '/usr/sbin/firmwarepasswd'
        CommandLine|contains:
            - 'setpasswd'
            - 'full'
            - 'delete'
            - 'check'
    condition: selection1
falsepositives:
    - Legitimate administration activities
level: medium
tags:
    - attack.impact

```
