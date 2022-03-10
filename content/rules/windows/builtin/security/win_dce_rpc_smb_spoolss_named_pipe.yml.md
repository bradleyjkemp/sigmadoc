---
title: "DCERPC SMB Spoolss Named Pipe"
aliases:
  - "/rule/214e8f95-100a-4e04-bb31-ef6cba8ce07e"


tags:
  - attack.lateral_movement
  - attack.t1021.002



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the use of the spoolss named pipe over SMB. This can be used to trigger the authentication via NTLM of any machine that has the spoolservice enabled.

<!--more-->


## Known false-positives

* Domain Controllers acting as printer servers too? :)



## References

* https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
* https://dirkjanm.io/a-different-way-of-abusing-zerologon/
* https://twitter.com/_dirkjan/status/1309214379003588608


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_dce_rpc_smb_spoolss_named_pipe.yml))
```yaml
title: DCERPC SMB Spoolss Named Pipe
id: 214e8f95-100a-4e04-bb31-ef6cba8ce07e
status: test
description: Detects the use of the spoolss named pipe over SMB. This can be used to trigger the authentication via NTLM of any machine that has the spoolservice enabled.
author: OTR (Open Threat Research)
references:
  - https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
  - https://dirkjanm.io/a-different-way-of-abusing-zerologon/
  - https://twitter.com/_dirkjan/status/1309214379003588608
date: 2018/11/28
modified: 2021/11/27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    ShareName: \\\*\IPC$
    RelativeTargetName: spoolss
  condition: selection
falsepositives:
  - 'Domain Controllers acting as printer servers too? :)'
level: medium
tags:
  - attack.lateral_movement
  - attack.t1021.002

```