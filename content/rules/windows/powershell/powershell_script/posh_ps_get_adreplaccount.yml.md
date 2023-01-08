---
title: "Suspicious Get-ADReplAccount"
aliases:
  - "/rule/060c3ef1-fd0a-4091-bf46-e7d625f60b73"
ruleid: 060c3ef1-fd0a-4091-bf46-e7d625f60b73

tags:
  - attack.credential_access
  - attack.t1003.006



status: experimental





date: Sun, 6 Feb 2022 11:15:00 +0100


---

The DSInternals PowerShell Module exposes several internal features of Active Directory and Azure Active Directory. These include FIDO2 and NGC key auditing, offline ntds.dit file manipulation, password auditing, DC recovery from IFM backups and password hash calculation.

<!--more-->


## Known false-positives

* Legitimate PowerShell scripts



## References

* https://www.powershellgallery.com/packages/DSInternals
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.006/T1003.006.md#atomic-test-2---run-dsinternals-get-adreplaccount


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_get_adreplaccount.yml))
```yaml
title: Suspicious Get-ADReplAccount
id: 060c3ef1-fd0a-4091-bf46-e7d625f60b73
status: experimental
description: 
  The DSInternals PowerShell Module exposes several internal features of Active Directory and Azure Active Directory.
  These include FIDO2 and NGC key auditing, offline ntds.dit file manipulation, password auditing, DC recovery from IFM backups and password hash calculation. 
date: 2022/02/06
author: frack113
references:
    - https://www.powershellgallery.com/packages/DSInternals
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.006/T1003.006.md#atomic-test-2---run-dsinternals-get-adreplaccount
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains|all: 
            - Get-ADReplAccount
            - '-All '
            - '-Server '
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: medium
tags:
    - attack.credential_access
    - attack.t1003.006

```
