---
title: "Clipboard Collection of Image Data with Xclip Tool"
aliases:
  - "/rule/f200dc3f-b219-425d-a17e-c38467364816"
ruleid: f200dc3f-b219-425d-a17e-c38467364816

tags:
  - attack.collection
  - attack.t1115



status: experimental





date: Fri, 1 Oct 2021 18:43:03 +0200


---

Detects attempts to collect image data stored in the clipboard from users with the usage of xclip tool. Xclip has to be installed. Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations.

<!--more-->


## Known false-positives

* Legitimate usage of xclip tools



## References

* https://attack.mitre.org/techniques/T1115/
* https://linux.die.net/man/1/xclip


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_clipboard_image_collection.yml))
```yaml
title: Clipboard Collection of Image Data with Xclip Tool
id: f200dc3f-b219-425d-a17e-c38467364816
description: Detects attempts to collect image data stored in the clipboard from users with the usage of xclip tool. Xclip has to be installed. Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations.
author: 'Pawel Mazur'
status: experimental
date: 2021/10/01
references: 
   - https://attack.mitre.org/techniques/T1115/
   - https://linux.die.net/man/1/xclip
logsource: 
   product: linux
   service: auditd
detection:
   xclip:
       type: EXECVE
       a0: xclip
       a1:
         - '-selection'
         - '-sel'
       a2: 
         - clipboard
         - clip
       a3: '-t'
       a4|startswith: 'image/'
       a5: '-o'
   condition: xclip
tags:
   - attack.collection
   - attack.t1115
falsepositives:
   - Legitimate usage of xclip tools
level: low 

```
