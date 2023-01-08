---
title: "Transferring Files with Credential Data via Network Shares"
aliases:
  - "/rule/910ab938-668b-401b-b08c-b596e80fdca5"
ruleid: 910ab938-668b-401b-b08c-b596e80fdca5

tags:
  - attack.credential_access
  - attack.t1003.002
  - attack.t1003.001
  - attack.t1003.003



status: test





date: Mon, 4 Nov 2019 04:26:34 +0300


---

Transferring files with well-known filenames (sensitive files with credential data) using network shares

<!--more-->


## Known false-positives

* Transferring sensitive files for legitimate administration work by legitimate administrator



## References

* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_transferring_files_with_credential_data_via_network_shares.yml))
```yaml
title: Transferring Files with Credential Data via Network Shares
id: 910ab938-668b-401b-b08c-b596e80fdca5
status: test
description: Transferring files with well-known filenames (sensitive files with credential data) using network shares
author: Teymur Kheirkhabarov, oscd.community
references:
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
date: 2019/10/22
modified: 2021/11/30
logsource:
  product: windows
  service: security
detection:
  selection:
    Provider_Name: Microsoft-Windows-Security-Auditing
    EventID: 5145
    RelativeTargetName|contains:
      - '\mimidrv'
      - '\lsass'
      - '\windows\minidump\'
      - '\hiberfil'
      - '\sqldmpr'
      - '\sam'
      - '\ntds.dit'
      - '\security'
  condition: selection
falsepositives:
  - Transferring sensitive files for legitimate administration work by legitimate administrator
level: medium
tags:
  - attack.credential_access
  - attack.t1003.002
  - attack.t1003.001
  - attack.t1003.003

```
