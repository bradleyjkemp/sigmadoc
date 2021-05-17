---
title: "Transferring Files with Credential Data via Network Shares - Zeek"
aliases:
  - "/rule/2e69f167-47b5-4ae7-a390-47764529eff5"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.002
  - attack.t1003.001
  - attack.t1003.003



status: experimental



level: medium



date: Sat, 2 May 2020 07:27:51 -0400


---

Transferring files with well-known filenames (sensitive files with credential data) using network shares

<!--more-->


## Known false-positives

* Transferring sensitive files for legitimate administration work by legitimate administrator



## References

* https://github.com/neo23x0/sigma/blob/373424f14574facf9e261d5c822345a282b91479/rules/windows/builtin/win_transferring_files_with_credential_data_via_network_shares.yml


## Raw rule
```yaml
title: Transferring Files with Credential Data via Network Shares - Zeek
id: 2e69f167-47b5-4ae7-a390-47764529eff5
description: Transferring files with well-known filenames (sensitive files with credential data) using network shares
author: '@neu5ron, Teymur Kheirkhabarov, oscd.community'
date: 2020/04/02
references:
    - https://github.com/neo23x0/sigma/blob/373424f14574facf9e261d5c822345a282b91479/rules/windows/builtin/win_transferring_files_with_credential_data_via_network_shares.yml
tags:
    - attack.credential_access
    - attack.t1003 # an old one
    - attack.t1003.002
    - attack.t1003.001
    - attack.t1003.003
logsource:
    product: zeek
    service: smb_files
detection:
    selection:
        name:
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
status: experimental

```
