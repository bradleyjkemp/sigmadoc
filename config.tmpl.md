---
title: "{{.Parsed.Title}}"

{{with .Time}}
date: {{.}}
{{end}}
---

## Raw config
```yaml
{{.Original}}
```
