---
title: "MITRE BZAR Indicators for Persistence"
aliases:
  - "/rule/53389db6-ba46-48e3-a94c-e0f2cefe1583"


tags:
  - attack.persistence
  - attack.t1547.004



status: test





date: Sat, 2 May 2020 07:27:51 -0400


---

Windows DCE-RPC functions which indicate a persistence techniques on the remote system. All credit for the Zeek mapping of the suspicious endpoint/operation field goes to MITRE.

<!--more-->


## Known false-positives

* Windows administrator tasks or troubleshooting
* Windows management scripts or software



## References

* https://github.com/mitre-attack/bzar#indicators-for-attck-persistence


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/zeek/zeek_dce_rpc_mitre_bzar_persistence.yml))
```yaml
title: MITRE BZAR Indicators for Persistence
id: 53389db6-ba46-48e3-a94c-e0f2cefe1583
status: test
description: 'Windows DCE-RPC functions which indicate a persistence techniques on the remote system. All credit for the Zeek mapping of the suspicious endpoint/operation field goes to MITRE.'
author: '@neu5ron, SOC Prime'
references:
  - https://github.com/mitre-attack/bzar#indicators-for-attck-persistence
date: 2020/03/19
modified: 2021/11/27
logsource:
  product: zeek
  service: dce_rpc
detection:
  op1:
    endpoint: 'spoolss'
    operation: 'RpcAddMonitor'
  op2:
    endpoint: 'spoolss'
    operation: 'RpcAddPrintProcessor'
  op3:
    endpoint: 'IRemoteWinspool'
    operation: 'RpcAsyncAddMonitor'
  op4:
    endpoint: 'IRemoteWinspool'
    operation: 'RpcAsyncAddPrintProcessor'
  op5:
    endpoint: 'ISecLogon'
    operation: 'SeclCreateProcessWithLogonW'
  op6:
    endpoint: 'ISecLogon'
    operation: 'SeclCreateProcessWithLogonExW'
  condition: 1 of op*
falsepositives:
  - 'Windows administrator tasks or troubleshooting'
  - 'Windows management scripts or software'
level: medium
tags:
  - attack.persistence
  - attack.t1547.004

```
