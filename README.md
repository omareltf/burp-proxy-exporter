# Proxy History Exporter — Burp Suite Extension

Lightweight Burp extension to export proxy history items as plain-text files. Select requests, right-click, export — done.

Useful for feeding raw HTTP traffic to an **AI agent** to automate vulnerability write-ups, build proof-of-concepts, or document findings without copy-pasting from Burp.

## Installation

1. Configure Jython: **Extender → Options → Python Environment** → point to `jython-standalone-2.7.x.jar` ([download](https://www.jython.org/download))
2. **Extender → Extensions → Add** → type **Python** → select `burp_exporter.py`

## Usage

1. In **Proxy → HTTP history**, select one or more items
2. Right-click:
   - **Export to directory…** — pick a folder (remembers the last one)
   - **Export to last dir** — instant export to the previously used folder
3. One file per item, named `<order>_request_<hash>.txt`

Files are ordered chronologically (oldest = 1). The 5-char hash uniquely identifies each request.

## Output

```
========================================================================
ITEM #1  [a3f2b]
URL: https://example.com/api/login
Method: POST
Target: https://example.com:443
========================================================================

------------------------------------------------------------------------
[REQUEST]
------------------------------------------------------------------------
POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username":"admin","password":"hunter2"}


------------------------------------------------------------------------
[RESPONSE]
------------------------------------------------------------------------
HTTP/1.1 200 OK
Content-Type: application/json

{"token":"eyJ..."}

========================================================================
```

## License

MIT
