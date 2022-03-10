---
title: "Azure Active Directory Hybrid Health AD FS New Server"
aliases:
  - "/rule/288a39fc-4914-4831-9ada-270e9dc12cb4"


tags:
  - attack.defense_evasion
  - attack.t1578



status: experimental





date: Thu, 26 Aug 2021 16:10:42 -0400


---

This detection uses AzureActivity logs (Administrative category) to identify the creation or update of a server instance in an Azure AD Hybrid health AD FS service.
A threat actor can create a new AD Health ADFS service and create a fake server instance to spoof AD FS signing logs. There is no need to compromise an on-prem AD FS server.
This can be done programmatically via HTTP requests to Azure.


<!--more-->


## Known false-positives

* legitimate AD FS servers added to an AAD Health AD FS service instance



## References

* https://o365blog.com/post/hybridhealthagent/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_aadhybridhealth_adfs_new_server.yml))
```yaml
title: Azure Active Directory Hybrid Health AD FS New Server
id: 288a39fc-4914-4831-9ada-270e9dc12cb4
description: |
  This detection uses AzureActivity logs (Administrative category) to identify the creation or update of a server instance in an Azure AD Hybrid health AD FS service.
  A threat actor can create a new AD Health ADFS service and create a fake server instance to spoof AD FS signing logs. There is no need to compromise an on-prem AD FS server.
  This can be done programmatically via HTTP requests to Azure.
status: experimental
date: 2021/08/26
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
tags:
  - attack.defense_evasion
  - attack.t1578
references:
  - https://o365blog.com/post/hybridhealthagent/
logsource:
  product: azure
  service: AzureActivity
detection:
  selection:
    CategoryValue: 'Administrative'
    ResourceProviderValue: 'Microsoft.ADHybridHealthService'
    ResourceId|contains: 'AdFederationService'
    OperationNameValue: 'Microsoft.ADHybridHealthService/services/servicemembers/action'
  condition: selection
falsepositives:
  - legitimate AD FS servers added to an AAD Health AD FS service instance
level: medium
```
