---
title: "Suspicious Export-PfxCertificate"
aliases:
  - "/rule/aa7a3fce-bef5-4311-9cc1-5f04bb8c308c"
ruleid: aa7a3fce-bef5-4311-9cc1-5f04bb8c308c

tags:
  - attack.credential_access
  - attack.t1552.004



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Commandlet that is used to export certificates from the local certificate store and sometimes used by threat actors to steal private keys from compromised machines

<!--more-->


## Known false-positives

* Legitimate certificate exports invoked by administrators or users (depends on processes in the environment - filter if unusable)



## References

* https://us-cert.cisa.gov/ncas/analysis-reports/ar21-112a
* https://docs.microsoft.com/en-us/powershell/module/pki/export-pfxcertificate


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_export_pfxcertificate.yml))
```yaml
title: Suspicious Export-PfxCertificate
id: aa7a3fce-bef5-4311-9cc1-5f04bb8c308c
status: experimental
description: Detects Commandlet that is used to export certificates from the local certificate store and sometimes used by threat actors to steal private keys from compromised machines
references:
    - https://us-cert.cisa.gov/ncas/analysis-reports/ar21-112a
    - https://docs.microsoft.com/en-us/powershell/module/pki/export-pfxcertificate
tags:
    - attack.credential_access
    - attack.t1552.004
author: Florian Roth
date: 2021/04/23
modified: 2021/08/04
logsource:
    product: windows
    category: ps_script
    definition: Script Block Logging must be enable
detection:
    PfxCertificate:
        ScriptBlockText|contains: 'Export-PfxCertificate'
    condition: PfxCertificate
falsepositives:
    - Legitimate certificate exports invoked by administrators or users (depends on processes in the environment - filter if unusable)
level: high

```
