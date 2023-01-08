---
title: "Accessing WinAPI in PowerShell"
aliases:
  - "/rule/03d83090-8cba-44a0-b02f-0b756a050306"
ruleid: 03d83090-8cba-44a0-b02f-0b756a050306

tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1106



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detecting use WinAPI Functions in PowerShell

<!--more-->


## Known false-positives

* Carbon PowerShell Module (https://github.com/webmd-health-services/Carbon)



## References

* https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_accessing_win_api.yml))
```yaml
title: Accessing WinAPI in PowerShell
id: 03d83090-8cba-44a0-b02f-0b756a050306
status: experimental
description: Detecting use WinAPI Functions in PowerShell
author: Nikita Nazarov, oscd.community
date: 2020/10/06
modified: 2022/02/23
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1106
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains:
            - 'WaitForSingleObject'
            - 'QueueUserApc'
            - 'RtlCreateUserThread'
            - 'OpenProcess'
            - 'VirtualAlloc'
            - 'VirtualFree'
            - 'WriteProcessMemory'
            - 'CreateUserThread'
            - 'CloseHandle'
            - 'GetDelegateForFunctionPointer'
            - 'CreateThread'
            - 'memcpy'
            - 'LoadLibrary'
            - 'GetModuleHandle'
            - 'GetProcAddress'
            - 'VirtualProtect'
            - 'FreeLibrary'
            - 'ReadProcessMemory'
            - 'CreateRemoteThread'
            - 'AdjustTokenPrivileges'
            # - 'WriteByte'  # FP with .NET System.IO.FileStream
            - 'WriteInt32'
            - 'OpenThreadToken'
            - 'PtrToString'
            - 'FreeHGlobal'
            - 'ZeroFreeGlobalAllocUnicode'
            - 'OpenProcessToken'
            - 'GetTokenInformation'
            - 'SetThreadToken'
            - 'ImpersonateLoggedOnUser'
            - 'RevertToSelf'
            - 'GetLogonSessionData'
            - 'CreateProcessWithToken'
            - 'DuplicateTokenEx'
            - 'OpenWindowStation'
            - 'OpenDesktop'
            - 'MiniDumpWriteDump'
            - 'AddSecurityPackage'
            - 'EnumerateSecurityPackages'
            - 'GetProcessHandle'
            - 'DangerousGetHandle'
            - 'kernel32'
            - 'Advapi32'
            - 'msvcrt'
            - 'ntdll'
            # - 'user32'  # FP with chocolatey
            - 'secur32'
    condition: selection
falsepositives:
    - Carbon PowerShell Module (https://github.com/webmd-health-services/Carbon)
level: high

```
