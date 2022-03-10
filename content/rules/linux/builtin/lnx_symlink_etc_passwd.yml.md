---
title: "Symlink Etc Passwd"
aliases:
  - "/rule/c67fc22a-0be5-4b4f-aad5-2b32c4b69523"


tags:
  - attack.t1204.001
  - attack.execution



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects suspicious command lines that look as if they would create symbolic links to /etc/passwd

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.qualys.com/2021/05/04/21nails/21nails.txt


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/builtin/lnx_symlink_etc_passwd.yml))
```yaml
title: Symlink Etc Passwd
id: c67fc22a-0be5-4b4f-aad5-2b32c4b69523
status: test
description: Detects suspicious command lines that look as if they would create symbolic links to /etc/passwd
author: Florian Roth
references:
  - https://www.qualys.com/2021/05/04/21nails/21nails.txt
date: 2019/04/05
modified: 2021/11/27
logsource:
  product: linux
detection:
  keywords:
    - 'ln -s -f /etc/passwd'
    - 'ln -s /etc/passwd'
  condition: keywords
falsepositives:
  - Unknown
level: high
tags:
  - attack.t1204.001
  - attack.execution

```
