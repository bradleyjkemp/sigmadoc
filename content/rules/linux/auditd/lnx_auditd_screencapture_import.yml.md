---
title: "Screen Capture with Import Tool"
aliases:
  - "/rule/dbe4b9c5-c254-4258-9688-d6af0b7967fd"


tags:
  - attack.collection
  - attack.t1113



status: experimental





date: Tue, 21 Sep 2021 18:55:48 +0200


---

Detects adversary creating screen capture of a desktop with Import Tool. Highly recommended using rule on servers, due to high usage of screenshot utilities on user workstations. ImageMagick must be installed.

<!--more-->


## Known false-positives

* Legitimate use of screenshot utility



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md
* https://attack.mitre.org/techniques/T1113/
* https://linux.die.net/man/1/import
* https://imagemagick.org/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_screencapture_import.yml))
```yaml
title: Screen Capture with Import Tool
id: dbe4b9c5-c254-4258-9688-d6af0b7967fd
description: Detects adversary creating screen capture of a desktop with Import Tool. Highly recommended using rule on servers, due to high usage of screenshot utilities on user workstations. ImageMagick must be installed.
author: 'Pawel Mazur'
status: experimental
date: 2021/09/21
references:
   - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md
   - https://attack.mitre.org/techniques/T1113/
   - https://linux.die.net/man/1/import
   - https://imagemagick.org/
logsource:
   product: linux
   service: auditd
detection:
   import:
       type: EXECVE
       a0: import
   import_window_root:
       a1: '-window'
       a2: 'root'
       a3|endswith:
         - '.png'
         - '.jpg'
         - '.jpeg'
   import_no_window_root:
       a1|endswith:
         - '.png'
         - '.jpg'
         - '.jpeg'
   condition: import and (import_window_root or import_no_window_root)
tags:
   - attack.collection
   - attack.t1113
falsepositives:
   - Legitimate use of screenshot utility
level: low
```
