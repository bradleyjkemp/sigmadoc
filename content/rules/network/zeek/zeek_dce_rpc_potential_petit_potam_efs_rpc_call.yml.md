---
title: "Potential PetitPotam Attack Via EFS RPC Calls"
aliases:
  - "/rule/4096842a-8f9f-4d36-92b4-d0b2a62f9b2a"


tags:
  - attack.t1557.001
  - attack.t1187



status: experimental





date: Mon, 23 Aug 2021 11:06:44 -0400


---

Detects usage of the windows RPC library Encrypting File System Remote Protocol (MS-EFSRPC). Variations of this RPC are used within the attack refereed to as PetitPotam.
The usage of this RPC function should be rare if ever used at all.
Thus usage of this function is uncommon enough that any usage of this RPC function should warrant further investigation to determine if it is legitimate.
 View surrounding logs (within a few minutes before and after) from the Source IP to. Logs from from the Source IP would include dce_rpc, smb_mapping, smb_files, rdp, ntlm, kerberos, etc..'


<!--more-->


## Known false-positives

* Uncommon but legitimate windows administrator or software tasks that make use of the Encrypting File System RPC Calls. Verify if this is common activity (see description).



## References

* https://github.com/topotam/PetitPotam/blob/main/PetitPotam/PetitPotam.cpp
* https://msrc.microsoft.com/update-guide/vulnerability/ADV210003
* https://vx-underground.org/archive/Symantec/windows-vista-network-attack-07-en.pdf
* https://threatpost.com/microsoft-petitpotam-poc/168163/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/zeek/zeek_dce_rpc_potential_petit_potam_efs_rpc_call.yml))
```yaml
title: Potential PetitPotam Attack Via EFS RPC Calls 
id: 4096842a-8f9f-4d36-92b4-d0b2a62f9b2a
description: |
    Detects usage of the windows RPC library Encrypting File System Remote Protocol (MS-EFSRPC). Variations of this RPC are used within the attack refereed to as PetitPotam.
    The usage of this RPC function should be rare if ever used at all.
    Thus usage of this function is uncommon enough that any usage of this RPC function should warrant further investigation to determine if it is legitimate.
     View surrounding logs (within a few minutes before and after) from the Source IP to. Logs from from the Source IP would include dce_rpc, smb_mapping, smb_files, rdp, ntlm, kerberos, etc..'
status: experimental
author: '@neu5ron, @Antonlovesdnb, Mike Remen'
date: 2021/08/17
references:
    - https://github.com/topotam/PetitPotam/blob/main/PetitPotam/PetitPotam.cpp
    - https://msrc.microsoft.com/update-guide/vulnerability/ADV210003
    - https://vx-underground.org/archive/Symantec/windows-vista-network-attack-07-en.pdf
    - https://threatpost.com/microsoft-petitpotam-poc/168163/
tags:
    - attack.t1557.001
    - attack.t1187
logsource:
    product: zeek
    service: dce_rpc
detection:
    efs_operation:
        operation|startswith:
            - 'Efs'
            - 'efs'
    condition: efs_operation
falsepositives:
    - Uncommon but legitimate windows administrator or software tasks that make use of the Encrypting File System RPC Calls. Verify if this is common activity (see description).
level: medium
fields:
    - id.orig_h
    - id.resp_h
    - id.resp_p
    - operation
    - endpoint
    - named_pipe
    - uid

```