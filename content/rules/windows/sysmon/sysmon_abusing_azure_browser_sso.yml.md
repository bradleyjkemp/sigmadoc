---
title: "Avusing Azure Browser SSO"
aliases:
  - "/rule/50f852e6-af22-4c78-9ede-42ef36aa3453"

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1073
  - attack.t1574.002



date: Wed, 15 Jul 2020 14:02:34 +0300


---

Detects abusing  Azure Browser SSO by requesting  OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser. An attacker can use this to authenticate to Azure AD in a browser as that user.

<!--more-->


## Known false-positives

* unknown




## Raw rule
```yaml
title: Avusing Azure Browser SSO
id: 50f852e6-af22-4c78-9ede-42ef36aa3453
description: Detects abusing  Azure Browser SSO by requesting  OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser. An attacker can use this to authenticate to Azure AD in a browser as that user.
author: Den Iuzvyk
reference:
   - https://posts.specterops.io/requesting-azure-ad-request-tokens-on-azure-ad-joined-machines-for-browser-sso-2b0409caad30
date: 2020/07/15
modified: 2020/08/26
logsource:
   category: sysmon
   product: windows
status: experimental
tags:
   - attack.defense_evasion
   - attack.privilege_escalation
   - attack.t1073          # an old one
   - attack.t1574.002
detection:
   condition: selection_dll and not filter_legit
   selection_dll:
      EventID: 7
      ImageLoaded|endswith: MicrosoftAccountTokenProvider.dll
   filter_legit:
      Image|endswith:
         - BackgroundTaskHost.exe
         - devenv.exe
         - iexplore.exe
         - MicrosoftEdge.exe
falsepositives:
   - unknown
level: high

```
