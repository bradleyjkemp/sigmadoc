---
title: "VBScript Payload Stored in Registry"
aliases:
  - "/rule/46490193-1b22-4c29-bdd6-5bf63907216f"


tags:
  - attack.persistence
  - attack.t1547.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects VBScript content stored into registry keys as seen being used by UNC2452 group

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_vbs_payload_stored.yml))
```yaml
title: VBScript Payload Stored in Registry
id: 46490193-1b22-4c29-bdd6-5bf63907216f
description: Detects VBScript content stored into registry keys as seen being used by UNC2452 group
status: experimental
date: 2021/03/05
modified: 2022/03/04
author: Florian Roth
references:
    - https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue 
        TargetObject|contains: 'Software\Microsoft\Windows\CurrentVersion'
        Details|contains: 
            - 'vbscript'
            - 'jscript'
            - 'mshtml'
            - 'RunHTMLApplication'
            - 'Execute('
            - 'CreateObject'
            - 'RegRead'
            - 'window.close'
    filter: 
        TargetObject|contains: 'Software\Microsoft\Windows\CurrentVersion\Run'
    filter_dotnet:
        Image|endswith: '\msiexec.exe'
        TargetObject|contains: '\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\'
        Details|contains:
            - '\Microsoft.NET\Primary Interop Assemblies\Microsoft.mshtml.dll'
            - '<\Microsoft.mshtml,fileVersion='
            - 'FL_Microsoft_mshtml_dll_____X86.'
            - 'Microsoft_mshtml_dll_1_____X86.'
            - '<\Microsoft.mshtml,culture='
    condition: selection and not 1 of filter*
falsepositives:
    - Unknown
level: high
tags:
    - attack.persistence
    - attack.t1547.001

```
