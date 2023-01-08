---
title: "SMB Spoolss Name Piped Usage"
aliases:
  - "/rule/bae2865c-5565-470d-b505-9496c87d0c30"
ruleid: bae2865c-5565-470d-b505-9496c87d0c30

tags:
  - attack.lateral_movement
  - attack.t1021.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the use of the spoolss named pipe over SMB. This can be used to trigger the authentication via NTLM of any machine that has the spoolservice enabled.

<!--more-->


## Known false-positives

* Domain Controllers that are sometimes, commonly although should not be, acting as printer servers too



## References

* https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
* https://dirkjanm.io/a-different-way-of-abusing-zerologon/
* https://twitter.com/_dirkjan/status/1309214379003588608


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/zeek/zeek_dce_rpc_smb_spoolss_named_pipe.yml))
```yaml
title: SMB Spoolss Name Piped Usage
id: bae2865c-5565-470d-b505-9496c87d0c30
description: Detects the use of the spoolss named pipe over SMB. This can be used to trigger the authentication via NTLM of any machine that has the spoolservice enabled.
status: experimental
author: OTR (Open Threat Research), @neu5ron
references:
    - https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
    - https://dirkjanm.io/a-different-way-of-abusing-zerologon/
    - https://twitter.com/_dirkjan/status/1309214379003588608
tags:
    - attack.lateral_movement
    - attack.t1021.002
date: 2018/11/28
modified: 2021/08/23
logsource:
    product: zeek
    service: smb_files
detection:
    selection:
        path|endswith: IPC$
        name: spoolss
    condition: selection
falsepositives:
    - Domain Controllers that are sometimes, commonly although should not be, acting as printer servers too
level: medium

```
