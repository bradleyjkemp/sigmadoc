---
title: "Steganography Extract Files with Steghide"
aliases:
  - "/rule/a5a827d9-1bbe-4952-9293-c59d897eb41b"
ruleid: a5a827d9-1bbe-4952-9293-c59d897eb41b

tags:
  - attack.defense_evasion
  - attack.t1027.003



status: experimental





date: Sat, 11 Sep 2021 10:56:17 +0200


---

Detects extraction of files with usage of steghide binary, the adversaries may use this technique to prevent the detection of hidden information.

<!--more-->


## Known false-positives

* None



## References

* https://attack.mitre.org/techniques/T1027/003/
* https://vitux.com/how-to-hide-confidential-files-in-images-on-debian-using-steganography/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_steghide_extract_steganography.yml))
```yaml
title: Steganography Extract Files with Steghide
id: a5a827d9-1bbe-4952-9293-c59d897eb41b
description: Detects extraction of files with usage of steghide binary, the adversaries may use this technique to prevent the detection of hidden information.
author: 'Pawel Mazur'
status: experimental
date: 2021/09/11
references:
   - https://attack.mitre.org/techniques/T1027/003/
   - https://vitux.com/how-to-hide-confidential-files-in-images-on-debian-using-steganography/
tags:
   - attack.defense_evasion
   - attack.t1027.003
falsepositives:
   - None
level: low
logsource:
   product: linux
   service: auditd
detection:
   Steghide: 
       type: EXECVE
       a0: steghide
       a1: extract
       a2: '-sf'
       a3|endswith:
         - '.jpg'
         - '.png'
   condition: Steghide

```
