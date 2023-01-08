---
title: "Certutil Encode"
aliases:
  - "/rule/e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a"
ruleid: e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a

tags:
  - attack.defense_evasion
  - attack.t1027



status: test





---

Detects suspicious a certutil command that used to encode files, which is sometimes used for data exfiltration

<!--more-->


## Known false-positives

* unknown



## References

* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
* https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_certutil_encode.yml))
```yaml
title: Certutil Encode
id: e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a
status: test
description: Detects suspicious a certutil command that used to encode files, which is sometimes used for data exfiltration
author: Florian Roth, Jonhnathan Ribeiro, oscd.community
references:
  - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
  - https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/
date: 2019/02/24
modified: 2022/01/07
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains|all:
      - '-f'
      - '-encode'
  condition: selection
falsepositives:
  - unknown
level: medium
tags:
  - attack.defense_evasion
  - attack.t1027

```
