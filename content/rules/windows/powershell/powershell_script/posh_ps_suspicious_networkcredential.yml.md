---
title: "Suspicious Connection to Remote Account"
aliases:
  - "/rule/1883444f-084b-419b-ac62-e0d0c5b3693f"


tags:
  - attack.credential_access
  - attack.t1110.001



status: experimental





date: Mon, 27 Dec 2021 20:25:01 +0100


---

Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.
Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism


<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.001/T1110.001.md#atomic-test-2---brute-force-credentials-of-single-active-directory-domain-user-via-ldap-against-domain-controller-ntlm-or-kerberos


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_networkcredential.yml))
```yaml
title: Suspicious Connection to Remote Account
id: 1883444f-084b-419b-ac62-e0d0c5b3693f
status: experimental
description: |
    Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.
    Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.001/T1110.001.md#atomic-test-2---brute-force-credentials-of-single-active-directory-domain-user-via-ldap-against-domain-controller-ntlm-or-kerberos
author: frack113
date: 2021/12/27
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains:
           - 'System.DirectoryServices.Protocols.LdapDirectoryIdentifier'
           - 'System.Net.NetworkCredential'
           - 'System.DirectoryServices.Protocols.LdapConnection'
    condition: selection
falsepositives:
    - unknown
level: low
tags:
    - attack.credential_access
    - attack.t1110.001
```