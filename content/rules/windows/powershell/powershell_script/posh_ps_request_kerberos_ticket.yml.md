---
title: "Request A Single Ticket via PowerShell"
aliases:
  - "/rule/a861d835-af37-4930-bcd6-5b178bfb54df"


tags:
  - attack.credential_access
  - attack.t1558.003



status: experimental





date: Wed, 29 Dec 2021 17:47:43 +0100


---

utilize native PowerShell Identity modules to query the domain to extract the Service Principal Names for a single computer.
This behavior is typically used during a kerberos or silver ticket attack.
A successful execution will output the SPNs for the endpoint in question.


<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md#atomic-test-4---request-a-single-ticket-via-powershell


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_request_kerberos_ticket.yml))
```yaml
title: Request A Single Ticket via PowerShell
id: a861d835-af37-4930-bcd6-5b178bfb54df
status: experimental
description: |
  utilize native PowerShell Identity modules to query the domain to extract the Service Principal Names for a single computer.
  This behavior is typically used during a kerberos or silver ticket attack.
  A successful execution will output the SPNs for the endpoint in question.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md#atomic-test-4---request-a-single-ticket-via-powershell
author: frack113
date: 2021/12/28
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains: System.IdentityModel.Tokens.KerberosRequestorSecurityToken
    condition: selection
falsepositives:
    - unknown
level: high
tags:
    - attack.credential_access
    - attack.t1558.003
```
