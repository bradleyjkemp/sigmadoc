---
title: "Antivirus Password Dumper Detection"
aliases:
  - "/rule/78cc2dd2-7d20-4d32-93ff-057084c38b93"


tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1558
  - attack.t1003.001
  - attack.t1003.002



status: test





date: Sun, 9 Sep 2018 11:03:26 +0200


---

Detects a highly relevant Antivirus alert that reports a password dumper

<!--more-->


## Known false-positives

* Unlikely



## References

* https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/
* https://www.virustotal.com/gui/file/5fcda49ee7f202559a6cbbb34edb65c33c9a1e0bde9fa2af06a6f11b55ded619/detection


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/application/antivirus/av_password_dumper.yml))
```yaml
title: Antivirus Password Dumper Detection
id: 78cc2dd2-7d20-4d32-93ff-057084c38b93
status: test
description: Detects a highly relevant Antivirus alert that reports a password dumper
author: Florian Roth
references:
  - https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/
  - https://www.virustotal.com/gui/file/5fcda49ee7f202559a6cbbb34edb65c33c9a1e0bde9fa2af06a6f11b55ded619/detection
date: 2018/09/09
modified: 2021/11/27
logsource:
  product: antivirus
detection:
  selection:
    Signature|contains:
      - 'DumpCreds'
      - 'Mimikatz'
      - 'PWCrack'
      - 'HTool/WCE'
      - 'PSWtool'
      - 'PWDump'
      - 'SecurityTool'
      - 'PShlSpy'
      - 'Rubeus'
      - 'Kekeo'
      - 'LsassDump'
      - 'Outflank'
  condition: selection
fields:
  - FileName
  - User
falsepositives:
  - Unlikely
level: critical
tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1558
  - attack.t1003.001
  - attack.t1003.002

```
