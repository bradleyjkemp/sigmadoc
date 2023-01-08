---
title: "New TaskCache Entry"
aliases:
  - "/rule/4720b7df-40c3-48fd-bbdf-fd4b3c464f0d"
ruleid: 4720b7df-40c3-48fd-bbdf-fd4b3c464f0d

tags:
  - attack.persistence
  - attack.t1053
  - attack.t1053.005



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Monitor the creation of a new key under 'TaskCache' when a new scheduled task is registered

<!--more-->


## Known false-positives

* Unknown



## References

* https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_taskcache_entry.yml))
```yaml
title: New TaskCache Entry
id: 4720b7df-40c3-48fd-bbdf-fd4b3c464f0d
description: Monitor the creation of a new key under 'TaskCache' when a new scheduled task is registered
status: experimental
tags:
  - attack.persistence
  - attack.t1053
  - attack.t1053.005
date: 2021/06/18
modified: 2022/03/03
references:
  - https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
author: Syed Hasan (@syedhasan009)
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    EventType: SetValue
    TargetObject|contains: 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\'
  filter:
    TargetObject|contains:
      - 'Microsoft\Windows\UpdateOrchestrator'
      - 'Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask\Index'
      - 'Microsoft\Windows\Flighting\OneSettings\RefreshCache\Index'
  filter_svchost:
    Image: 'C:\WINDOWS\system32\svchost.exe'
    TargetObject|contains:
      - 'Microsoft\Windows\WindowsUpdate\Scheduled Start\Index'
      - 'Microsoft\Windows\PushToInstall\Registration\Index'
      - 'Microsoft\Windows\GroupPolicy\{*}\Index'
      - '\TaskCache\Tree\Opera scheduled Autoupdate'
      - '\TaskCache\Tree\Opera scheduled assistant Autoupdate'
      - '\TaskCache\Tree\OneDrive Reporting'
      - '\TaskCache\Tree\OneDrive Standalone Update Task'
      - '\TaskCache\Tree\Mozilla\SD'
      - '\TaskCache\Tree\Microsoft\Windows\.NET Framework\.NET Framework '
      - '\TaskCache\Tree\Microsoft\Office\OfficeOsfInstaller\'
      - '\TaskCache\Tree\Microsoft\Office\OfficeBackgroundTaskHandler' # *Logon and *Registration
      - '\TaskCache\Tree\GoogleUpdateTaskMachine' # *Core and *UA
      - '\TaskCache\Tree\DropboxUpdateTaskMachine' # *Core and *UA
      - '\TaskCache\Tree\Mozilla\Firefox Default Browser Agent '
      - '\TaskCache\Tree\Mozilla\Firefox Background Update '
      - '\TaskCache\Tree\Microsoft\Windows\WOF\WIM-Hash-Validation\Index'
      - '\TaskCache\Tree\Microsoft\Office\SD'
      - '\TaskCache\Tree\Microsoft\Office\OfficeTelemetry' # *AgentLogOn and *AgentFallBack
      - '\TaskCache\Tree\Microsoft\Office\Office ClickToRun Service Monitor\'
      - '\TaskCache\Tree\Microsoft\Office\Office Automatic Updates 2.0\'
      - '\TaskCache\Tree\klcp_update\'
      - '\TaskCache\Tree\Apple\SD'
      - '\TaskCache\Tree\Apple\AppleSoftwareUpdate\'
      - '\TaskCache\Tree\Microsoft\Windows\Windows Defender\Windows Defender Verification\'
      - '\TaskCache\Tree\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance\'
      - '\TaskCache\Tree\Microsoft\Windows\Windows Defender\Windows Defender Cleanup\'
      - '\TaskCache\Tree\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan\'
  condition: selection and not 1 of filter*
falsepositives:
  - Unknown
level: medium
```
