---
title: "New Federated Domain Added"
aliases:
  - "/rule/42127bdd-9133-474f-a6f1-97b6c08a4339"


tags:
  - attack.persistence
  - attack.t1136.003



status: experimental





date: Tue, 8 Feb 2022 10:31:47 +0100


---

Alert for the addition of a new federated domain.

<!--more-->


## Known false-positives

* The creation of a new Federated domain is not necessarily malicious, however these events need to be followed closely, as it may indicate federated credential abuse or backdoor via federated identities at a similar or different cloud provider.



## References

* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf
* https://us-cert.cisa.gov/ncas/alerts/aa21-008a
* https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html
* https://www.sygnia.co/golden-saml-advisory
* https://o365blog.com/post/aadbackdoor/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/m365/microsoft365_new_federated_domain_added.yml))
```yaml
title: New Federated Domain Added
id: 42127bdd-9133-474f-a6f1-97b6c08a4339
status: experimental
description: Alert for the addition of a new federated domain.
author: '@ionsor'
date: 2022/02/08
references:
    - https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf
    - https://us-cert.cisa.gov/ncas/alerts/aa21-008a
    - https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html
    - https://www.sygnia.co/golden-saml-advisory
    - https://o365blog.com/post/aadbackdoor/
logsource:
    category: Exchange
    product: m365
detection:
    selection:
        eventSource: Exchange
        eventName: 'Add-FederatedDomain'
        status: success
    condition: selection
falsepositives:
    - The creation of a new Federated domain is not necessarily malicious, however these events need to be followed closely, as it may indicate federated credential abuse or backdoor via federated identities at a similar or different cloud provider.
level: medium
tags:
    - attack.persistence
    - attack.t1136.003

```
