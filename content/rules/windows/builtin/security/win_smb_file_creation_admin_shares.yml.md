---
title: "SMB Create Remote File Admin Share"
aliases:
  - "/rule/b210394c-ba12-4f89-9117-44a2464b9511"
ruleid: b210394c-ba12-4f89-9117-44a2464b9511

tags:
  - attack.lateral_movement
  - attack.t1021.002



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Look for non-system accounts SMB accessing a file with write (0x2) access mask via administrative share (i.e C$).

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/OTRF/ThreatHunter-Playbook/blob/master/playbooks/WIN-201012004336.yaml
* https://securitydatasets.com/notebooks/small/windows/08_lateral_movement/SDWIN-200806015757.html?highlight=create%20file


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_smb_file_creation_admin_shares.yml))
```yaml
title: SMB Create Remote File Admin Share
id: b210394c-ba12-4f89-9117-44a2464b9511
status: test
description: Look for non-system accounts SMB accessing a file with write (0x2) access mask via administrative share (i.e C$).
author: Jose Rodriguez (@Cyb3rPandaH), OTR (Open Threat Research)
references:
  - https://github.com/OTRF/ThreatHunter-Playbook/blob/master/playbooks/WIN-201012004336.yaml
  - https://securitydatasets.com/notebooks/small/windows/08_lateral_movement/SDWIN-200806015757.html?highlight=create%20file
date: 2020/08/06
modified: 2021/11/27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    ShareName|endswith: 'C$'
    AccessMask: '0x2'
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
falsepositives:
  - Unknown
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.002

```
