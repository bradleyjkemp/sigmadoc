---
title: "Bypass UAC Using SilentCleanup Task"
aliases:
  - "/rule/724ea201-6514-4f38-9739-e5973c34f49a"
ruleid: 724ea201-6514-4f38-9739-e5973c34f49a

tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1548.002



status: experimental





date: Sat, 8 Jan 2022 09:17:56 +0100


---

There is an auto-elevated task called SilentCleanup located in %windir%\system32\cleanmgr.exe This can be abused to elevate any file with Administrator privileges without prompting UAC

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-9---bypass-uac-using-silentcleanup-task
* https://www.reddit.com/r/hacking/comments/ajtrws/bypassing_highest_uac_level_windows_810/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_bypass_uac_using_silentcleanup_task.yml))
```yaml
title: Bypass UAC Using SilentCleanup Task
id: 724ea201-6514-4f38-9739-e5973c34f49a
description: There is an auto-elevated task called SilentCleanup located in %windir%\system32\cleanmgr.exe This can be abused to elevate any file with Administrator privileges without prompting UAC
author: frack113
date: 2022/01/06
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-9---bypass-uac-using-silentcleanup-task
    - https://www.reddit.com/r/hacking/comments/ajtrws/bypassing_highest_uac_level_windows_810/
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Environment\windir'
        Details|contains: '&REM'
        EventType: SetValue
    condition: selection
falsepositives:
    - Unknown
level: high
tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1548.002
```
