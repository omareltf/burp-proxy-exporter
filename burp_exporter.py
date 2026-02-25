# -*- coding: utf-8 -*-
"""
Proxy History Exporter - Burp Suite Extension

Exports selected proxy history items to individual text files containing
the full HTTP request and response as shown in the proxy history.

Usage:
  1. Load this extension in Burp Suite (Extender > Extensions > Add)
  2. In the Proxy > HTTP history tab, select one or more items
  3. Right-click and choose "Export to directory..." or "Export to last dir"
  4. Files are created as <order>_request_<hash>.txt
"""

from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem, JFileChooser, JOptionPane
from java.awt.event import ActionListener
import hashlib
import os


# ---------------------------------------------------------------------------
# Proper ActionListener to avoid Jython double-fire bug with lambdas
# ---------------------------------------------------------------------------

class _ExportAction(ActionListener):
    """Swing ActionListener that calls the export handler exactly once."""
    def __init__(self, handler, invocation, ask_dir):
        self._handler = handler
        self._invocation = invocation
        self._ask_dir = ask_dir

    def actionPerformed(self, event):
        self._handler(self._invocation, self._ask_dir)


class BurpExtender(IBurpExtender, IContextMenuFactory):
    """Burp extension that exports proxy history items to text files."""

    EXTENSION_NAME = "Proxy History Exporter"

    # -------------------------------------------------------------------------
    # Extension setup
    # -------------------------------------------------------------------------

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Remember last export directory so the file chooser reopens there
        self._last_export_dir = None

        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.registerContextMenuFactory(self)

        callbacks.printOutput("[*] %s loaded successfully" % self.EXTENSION_NAME)
        callbacks.printOutput("[*] Right-click items in Proxy > HTTP history to export")

    # -------------------------------------------------------------------------
    # IContextMenuFactory — right-click menu in proxy history
    # -------------------------------------------------------------------------

    def createMenuItems(self, invocation):
        ctx = invocation.getInvocationContext()
        if ctx != IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
            return None

        items = []

        item1 = JMenuItem("Export to directory...")
        item1.addActionListener(_ExportAction(self._do_export, invocation, True))
        items.append(item1)

        item2 = JMenuItem("Export to last dir")
        item2.addActionListener(_ExportAction(self._do_export, invocation, False))
        if self._last_export_dir is None:
            item2.setToolTipText("No previous directory - will prompt for one")
        else:
            item2.setToolTipText(self._last_export_dir)
        items.append(item2)

        return items

    # -------------------------------------------------------------------------
    # Export logic
    # -------------------------------------------------------------------------

    @staticmethod
    def _make_hash(msg):
        """Generate a unique 5-character hex hash for a message."""
        h = hashlib.sha256()
        req = msg.getRequest()
        resp = msg.getResponse()
        svc = msg.getHttpService()
        if svc:
            h.update(str(svc.getHost()))
            h.update(str(svc.getPort()))
        if req:
            h.update(str(bytearray(req)))
        if resp:
            h.update(str(bytearray(resp)))
        return h.hexdigest()[:5]

    def _do_export(self, invocation, ask_dir):
        """Export selected messages. If ask_dir is True, always prompt."""

        # Determine export directory
        if ask_dir or self._last_export_dir is None:
            if self._last_export_dir is not None:
                chooser = JFileChooser(self._last_export_dir)
            else:
                chooser = JFileChooser()
            chooser.setDialogTitle("Select export directory")
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
            chooser.setAcceptAllFileFilterUsed(False)

            if chooser.showOpenDialog(None) != JFileChooser.APPROVE_OPTION:
                return

            export_dir = chooser.getSelectedFile().getAbsolutePath()
            self._last_export_dir = export_dir
        else:
            export_dir = self._last_export_dir

        messages = invocation.getSelectedMessages()
        if not messages or len(messages) == 0:
            return

        # Reverse: Burp gives newest first, we want oldest = 1
        messages = list(reversed(messages))

        total = len(messages)
        pad = len(str(total))
        exported = 0
        errors = []

        for idx, msg in enumerate(messages):
            try:
                order = idx + 1
                h = self._make_hash(msg)

                current_req = msg.getRequest()
                current_resp = msg.getResponse()

                # Build and write file
                content = self._format_export(
                    order, h, msg,
                    current_req, current_resp,
                )

                filename = "%s_request_%s.txt" % (str(order).zfill(pad), h)
                filepath = os.path.join(export_dir, filename)

                f = open(filepath, "wb")
                try:
                    f.write(content)
                finally:
                    f.close()

                exported += 1
                self._callbacks.printOutput("[+] Exported: %s" % filename)

            except Exception as e:
                errors.append(str(e))
                self._callbacks.printError(
                    "[-] Error exporting item %d: %s" % (idx, str(e))
                )

        # Summary dialog
        result = "Exported %d item(s) to:\n%s" % (exported, export_dir)
        if errors:
            result += "\n\nFailed: %d item(s)" % len(errors)

        JOptionPane.showMessageDialog(
            None,
            result,
            self.EXTENSION_NAME,
            JOptionPane.INFORMATION_MESSAGE,
        )

    # -------------------------------------------------------------------------
    # Formatting helpers
    # -------------------------------------------------------------------------

    def _format_export(
        self,
        order,
        hash_id,
        msg,
        current_req,
        current_resp,
    ):
        """Return the full file content (as a str/bytes) for one proxy item."""

        SEP = "=" * 72
        LINE = "-" * 72

        # -- metadata --
        service = msg.getHttpService()
        url = ""
        method = ""

        if current_req is not None:
            try:
                info = self._helpers.analyzeRequest(msg)
                url = str(info.getUrl())
                method = str(info.getMethod())
            except Exception:
                pass

        parts = []

        parts.append(SEP)
        parts.append("ITEM #%d  [%s]" % (order, hash_id))
        parts.append("URL: %s" % url)
        parts.append("Method: %s" % method)

        if service:
            parts.append(
                "Target: %s://%s:%d"
                % (service.getProtocol(), service.getHost(), service.getPort())
            )

        comment = msg.getComment()
        if comment:
            parts.append("Comment: %s" % comment)

        parts.append(SEP)
        parts.append("")

        # -- request --
        parts.append(LINE)
        parts.append("[REQUEST]")
        parts.append(LINE)
        if current_req is not None:
            parts.append(self._bytes_to_str(current_req))
        else:
            parts.append("(no request data)")

        parts.append("")
        parts.append("")

        # -- response --
        parts.append(LINE)
        parts.append("[RESPONSE]")
        parts.append(LINE)
        if current_resp is not None:
            parts.append(self._bytes_to_str(current_resp))
        else:
            parts.append("(no response received)")

        parts.append("")
        parts.append(SEP)

        return "\n".join(parts)

    @staticmethod
    def _bytes_to_str(data):
        """Convert Java byte[] / Python bytearray to a str preserving raw bytes."""
        if data is None:
            return ""
        try:
            ba = data if isinstance(data, bytearray) else bytearray(data)
            return str(ba)
        except Exception:
            return "(binary data, %d bytes)" % len(data)
