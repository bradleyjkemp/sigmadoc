---
title: "Suspicious VSFTPD Error Messages"
aliases:
  - "/rule/377f33a1-4b36-4ee1-acee-1dbe4b43cfbe"


tags:
  - attack.initial_access
  - attack.t1190



status: test





date: Wed, 5 Jul 2017 18:59:51 -0600


---

Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/dagwieers/vsftpd/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/other/lnx_susp_vsftp.yml))
```yaml
title: Suspicious VSFTPD Error Messages
id: 377f33a1-4b36-4ee1-acee-1dbe4b43cfbe
status: test
description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
author: Florian Roth
references:
  - https://github.com/dagwieers/vsftpd/
date: 2017/07/05
modified: 2021/11/27
logsource:
  product: linux
  service: vsftpd
detection:
  keywords:
    - 'Connection refused: too many sessions for this address.'
    - 'Connection refused: tcp_wrappers denial.'
    - 'Bad HTTP verb.'
    - 'port and pasv both active'
    - 'pasv and port both active'
    - 'Transfer done (but failed to open directory).'
    - 'Could not set file modification time.'
    - 'bug: pid active in ptrace_sandbox_free'
    - 'PTRACE_SETOPTIONS failure'
    - 'weird status:'
    - 'couldn''t handle sandbox event'
    - 'syscall * out of bounds'
    - 'syscall not permitted:'
    - 'syscall validate failed:'
    - 'Input line too long.'
    - 'poor buffer accounting in str_netfd_alloc'
    - 'vsf_sysutil_read_loop'
  condition: keywords
falsepositives:
  - Unknown
level: medium
tags:
  - attack.initial_access
  - attack.t1190

```