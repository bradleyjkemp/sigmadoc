---
title: "Deletes Backup Files"
aliases:
  - "/rule/06125661-3814-4e03-bfa2-1e4411c60ac3"


tags:
  - attack.impact
  - attack.t1490



status: experimental





date: Sun, 2 Jan 2022 10:36:52 +0100


---

Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.

<!--more-->


## Known false-positives

* Legitime usage



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-6---windows---delete-backup-files


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_delete/file_delete_win_delete_backup_file.yml))
```yaml
title: Deletes Backup Files
id: 06125661-3814-4e03-bfa2-1e4411c60ac3
status: experimental
description: Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.
author: frack113
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-6---windows---delete-backup-files
date: 2022/01/02
logsource:
  product: windows
  category: file_delete
detection:
  selection:
    Image|endswith: cmd.exe 
    TargetFilename|endswith:
      - '.VHD'
      - '.bac'
      - '.bak'
      - '.wbcat'
      - '.bkf'
      - '.set'
      - '.win'
      - '.dsk'
  condition: selection
falsepositives:
  - Legitime usage 
level: medium
tags:
  - attack.impact
  - attack.t1490

```
