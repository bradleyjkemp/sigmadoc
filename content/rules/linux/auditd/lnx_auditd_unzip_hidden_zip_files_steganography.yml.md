---
title: "Steganography Unzip Hidden Information From Picture File"
aliases:
  - "/rule/edd595d7-7895-4fa7-acb3-85a18a8772ca"
ruleid: edd595d7-7895-4fa7-acb3-85a18a8772ca

tags:
  - attack.defense_evasion
  - attack.t1027.003



status: experimental





date: Thu, 9 Sep 2021 16:13:27 +0200


---

Detects extracting of zip file from image file

<!--more-->


## Known false-positives

* None



## References

* https://attack.mitre.org/techniques/T1027/003/
* https://zerotoroot.me/steganography-hiding-a-zip-in-a-jpeg-file/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_unzip_hidden_zip_files_steganography.yml))
```yaml
title: Steganography Unzip Hidden Information From Picture File
id: edd595d7-7895-4fa7-acb3-85a18a8772ca
description: Detects extracting of zip file from image file
author: 'Pawel Mazur'
status: experimental
date: 2021/09/09
references:
   - https://attack.mitre.org/techniques/T1027/003/
   - https://zerotoroot.me/steganography-hiding-a-zip-in-a-jpeg-file/
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
   commands:
       type: EXECVE
       a0:
           - unzip
   a1:
       a1|endswith:
           - '.jpg'
           - '.png'
   condition: commands and a1

```
