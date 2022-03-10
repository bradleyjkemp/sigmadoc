---
title: "Suspicious SSL Connection"
aliases:
  - "/rule/195626f3-5f1b-4403-93b7-e6cfd4d6a078"


tags:
  - attack.command_and_control
  - attack.t1573



status: experimental





date: Sun, 23 Jan 2022 11:37:01 +0100


---

Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.

<!--more-->


## Known false-positives

* legitimate administrative script



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1573/T1573.md#atomic-test-1---openssl-c2
* https://medium.com/walmartglobaltech/openssl-server-reverse-shell-from-windows-client-aee2dbfa0926


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_susp_ssl_keyword.yml))
```yaml
title: Suspicious SSL Connection
id: 195626f3-5f1b-4403-93b7-e6cfd4d6a078
status: experimental
description: Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1573/T1573.md#atomic-test-1---openssl-c2
    - https://medium.com/walmartglobaltech/openssl-server-reverse-shell-from-windows-client-aee2dbfa0926
author: frack113
date: 2022/01/23
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains|all:
            - System.Net.Security.SslStream
            - Net.Security.RemoteCertificateValidationCallback
            - '.AuthenticateAsClient'
    condition: selection 
falsepositives:
  - legitimate administrative script
level: low
tags:
  - attack.command_and_control
  - attack.t1573

```
