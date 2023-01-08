---
title: "Azure AD Health Service Agents Registry Keys Access"
aliases:
  - "/rule/1d2ab8ac-1a01-423b-9c39-001510eae8e8"
ruleid: 1d2ab8ac-1a01-423b-9c39-001510eae8e8

tags:
  - attack.discovery
  - attack.t1012



status: experimental





date: Thu, 26 Aug 2021 16:10:42 -0400


---

This detection uses Windows security events to detect suspicious access attempts to the registry key values and sub-keys of Azure AD Health service agents (e.g AD FS).
Information from AD Health service agents can be used to potentially abuse some of the features provided by those services in the cloud (e.g. Federation).
This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable object: HKLM:\SOFTWARE\Microsoft\ADHealthAgent.
Make sure you set the SACL to propagate to its sub-keys.


<!--more-->


## Known false-positives

* Unknown



## References

* https://o365blog.com/post/hybridhealthagent/
* https://github.com/OTRF/Set-AuditRule/blob/master/rules/registry/aad_connect_health_service_agent.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_aadhealth_svc_agent_regkey_access.yml))
```yaml
title: Azure AD Health Service Agents Registry Keys Access
id: 1d2ab8ac-1a01-423b-9c39-001510eae8e8
description: |
    This detection uses Windows security events to detect suspicious access attempts to the registry key values and sub-keys of Azure AD Health service agents (e.g AD FS).
    Information from AD Health service agents can be used to potentially abuse some of the features provided by those services in the cloud (e.g. Federation).
    This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable object: HKLM:\SOFTWARE\Microsoft\ADHealthAgent.
    Make sure you set the SACL to propagate to its sub-keys.
status: experimental
date: 2021/08/26
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
tags:
    - attack.discovery
    - attack.t1012
references:
  - https://o365blog.com/post/hybridhealthagent/
  - https://github.com/OTRF/Set-AuditRule/blob/master/rules/registry/aad_connect_health_service_agent.yml
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4663
        ObjectType: 'Key'
        ObjectName: '\REGISTRY\MACHINE\SOFTWARE\Microsoft\ADHealthAgent'
    filter:
        ProcessName|contains:
            - 'Microsoft.Identity.Health.Adfs.DiagnosticsAgent.exe'
            - 'Microsoft.Identity.Health.Adfs.InsightsService.exe'
            - 'Microsoft.Identity.Health.Adfs.MonitoringAgent.Startup.exe'
            - 'Microsoft.Identity.Health.Adfs.PshSurrogate.exe'
            - 'Microsoft.Identity.Health.Common.Clients.ResourceMonitor.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium

```
