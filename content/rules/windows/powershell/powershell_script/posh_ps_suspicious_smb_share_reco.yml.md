---
title: "Suspicious Get Information for SMB Share"
aliases:
  - "/rule/95f0643a-ed40-467c-806b-aac9542ec5ab"
ruleid: 95f0643a-ed40-467c-806b-aac9542ec5ab

tags:
  - attack.discovery
  - attack.t1069.001



status: experimental





date: Wed, 15 Dec 2021 19:36:16 +0100


---

Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and
to identify potential systems of interest for Lateral Movement.
Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network. 


<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_smb_share_reco.yml))
```yaml
title: Suspicious Get Information for SMB Share
id: 95f0643a-ed40-467c-806b-aac9542ec5ab
description: |
  Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and
  to identify potential systems of interest for Lateral Movement.
  Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network. 
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md
status: experimental
author: frack113
date: 2021/12/15
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains: get-smbshare
    condition: selection
falsepositives:
    - unknown
level: low
tags:
    - attack.discovery
    - attack.t1069.001
```
