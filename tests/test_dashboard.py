"""Static integrity tests for the web dashboard template.

These guard the exact classes of bug that previously broke the dashboard:

1. A missing ``</section>`` tag nested four pages inside another page, so they
   rendered completely blank (Scheduling, Diff View, Team Projects, Rules).
2. ``onclick`` handlers referencing functions that were never defined.
3. JS calling functions that do not exist (``generateScanId``,
   ``connectProgressWS``, ``disconnectProgressWS``) and reading undeclared
   variables (``wsProgress``), which broke folder drag-drop scanning.
4. Modal markup (``.modal-overlay`` etc.) with no matching CSS, so every dialog
   rendered as a giant inline form over the pages.
5. Frontend ``fetch()`` URLs that do not exist in the backend (``/api/projects``
   instead of ``/projects``), which made Team Projects load nothing.
"""

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

from secret_scanner.api.app import app

TEMPLATE = (
    Path(__file__).resolve().parent.parent
    / "secret_scanner" / "api" / "templates" / "index.html"
)
HTML = TEMPLATE.read_text(encoding="utf-8")
CSS = re.search(r"<style>([\s\S]*?)</style>", HTML).group(1)
SCRIPT = re.search(r"<script>([\s\S]*)</script>", HTML).group(1)

#: Every page the sidebar exposes. All of them must render when clicked.
EXPECTED_PAGES = [
    "page-path", "page-text", "page-git", "page-url", "page-results",
    "page-overview", "page-history", "page-schedule", "page-diff",
    "page-projects", "page-rules",
]

TRACKED_TAGS = {"section", "div", "main", "body"}

#: Javascript/browser built-ins that are legitimately not defined in the script.
JS_BUILTINS = {"if", "for", "while", "switch", "catch", "return", "typeof", "new", "delete", "void", "in", "of", "do", "else", "try", "finally", "throw", "case", "break", "continue", "function", "async", "await", "yield", "class", "extends", "super", "this", "String", "Number", "Boolean", "Array", "Object", "Math", "JSON", "Date", "RegExp", "Set", "Map", "WeakMap", "Promise", "Error", "TypeError", "RangeError", "SyntaxError", "parseFloat", "parseInt", "isNaN", "isFinite", "encodeURIComponent", "decodeURIComponent", "eval", "setTimeout", "setInterval", "clearTimeout", "clearInterval", "requestAnimationFrame", "structuredClone", "fetch", "console", "alert", "confirm", "prompt", "FormData", "Blob", "File", "FileReader", "URL", "URLSearchParams", "WebSocket", "Response", "Request", "Headers", "AbortController", "Intl", "Symbol", "BigInt", "Proxy", "Reflect", "escape", "unescape", "atob", "btoa", "queueMicrotask", "document", "window", "localStorage", "sessionStorage", "navigator", "location", "history", "screen", "getComputedStyle", "matchMedia", "CustomEvent", "Event"}


#: Characters after which a ``/`` starts a regex literal rather than division.
_REGEX_PRECEDERS = set("(,=:[!&|?{;\n")
#: Keywords after which a ``/`` starts a regex (``return /pat/.test(x)``).
_REGEX_KEYWORDS = {
    "return", "case", "typeof", "new", "delete", "void", "do", "else",
    "yield", "await", "in", "of",
}


def _starts_regex(js: str, i: int, prev: str) -> bool:
    """True when the ``/`` at index i opens a regex literal, not division."""
    if prev == "" or prev in _REGEX_PRECEDERS:
        return True
    if prev.isalnum() or prev in "_$":
        # Only keywords (return, case, ...) may be followed by a regex.
        m = re.search(r"([A-Za-z_$][\w$]*)\s*$", js[:i])
        return bool(m) and m.group(1) in _REGEX_KEYWORDS
    return False


def _strip_comments_and_strings(js: str) -> str:
    """Remove comments, string/template literals and regex literals.

    Regex literals must be handled explicitly: in ``.replace(/"/g, ...)``
    the ``"`` inside the regex would otherwise open a phantom string and
    scramble quote parity for the rest of the file, leaking HTML/CSS
    template content into the "code" we audit for undefined calls.
    """
    out: list[str] = []
    i, n = 0, len(js)
    prev = ""  # last significant code character (whitespace/comments excluded)
    while i < n:
        ch = js[i]
        nxt = js[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            j = js.find("\n", i)
            i = n if j == -1 else j
        elif ch == "/" and nxt == "*":
            j = js.find("*/", i + 2)
            i = n if j == -1 else j + 2
        elif ch == "/" and _starts_regex(js, i, prev):
            # Skip /pattern/flags, honouring backslashes and [classes].
            i += 1
            in_class = False
            while i < n:
                c = js[i]
                if c == "\\":
                    i += 2
                    continue
                if c == "[":
                    in_class = True
                elif c == "]":
                    in_class = False
                elif c == "/" and not in_class:
                    i += 1
                    break
                elif c == "\n":  # not a regex after all; resync at the line end
                    break
                i += 1
            while i < n and js[i] in "dgimsuvy":  # regex flags
                i += 1
            prev = "/"  # a regex is an expression value
        elif ch in "\"'`":
            quote = ch
            i += 1
            while i < n:
                if js[i] == "\\":
                    i += 2
                    continue
                if js[i] == quote:
                    i += 1
                    break
                # keep template-literal expressions: ${ ... }
                if quote == "`" and js[i] == "$" and i + 1 < n and js[i + 1] == "{":
                    depth = 1
                    i += 2
                    while i < n and depth:
                        if js[i] == "{":
                            depth += 1
                        elif js[i] == "}":
                            depth -= 1
                        i += 1
                    continue
                i += 1
            # A finished literal is a value, so a following "/" is division.
            prev = "'"
        else:
            out.append(ch)
            if not ch.isspace():
                prev = ch
            i += 1
    return "".join(out)


class _StructureParser(HTMLParser):
    """Tracks section nesting so misnested/blank pages are caught."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.page_parents: dict[str, str | None] = {}
        self.problems: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag not in TRACKED_TAGS:
            return
        attrs_d = dict(attrs)
        elem_id = attrs_d.get("id")

        if tag == "section" and "page" in (attrs_d.get("class") or "").split() and elem_id:
            parent = next((s for s in reversed(self.stack) if s.startswith("section")), None)
            self.page_parents[elem_id] = parent
            if parent:
                self.problems.append(f"{elem_id} is nested inside {parent}")
        self.stack.append(f"{tag}#{elem_id or ''}")

    def handle_endtag(self, tag):
        if tag not in TRACKED_TAGS:
            return
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i].startswith(tag + "#"):
                for orphan in self.stack[i + 1:]:
                    self.problems.append(f"unclosed <{orphan}>")
                del self.stack[i:]
                return
        self.problems.append(f"stray </{tag}>")


class TestDashboardStructure(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.parser = _StructureParser()
        cls.parser.feed(HTML)

    def test_every_page_exists(self):
        for page in EXPECTED_PAGES:
            self.assertIn(f'id="{page}"', HTML, f"{page} section missing")

    def test_page_sections_are_top_level_siblings(self):
        """A missing </section> used to nest 4 pages inside page-history, hiding them."""
        nested = {
            pid: parent
            for pid, parent in self.parser.page_parents.items()
            if parent is not None
        }
        self.assertEqual(nested, {}, f"page sections are nested inside another page: {nested}")

    def test_no_unclosed_or_stray_tags(self):
        self.assertEqual(self.parser.problems, [], f"malformed HTML: {self.parser.problems}")

    def test_all_page_ids_present(self):
        self.assertEqual(
            sorted(self.parser.page_parents), sorted(EXPECTED_PAGES),
            "sidebar pages and page sections are out of sync",
        )

    def test_every_nav_button_targets_an_existing_page(self):
        for nav in re.findall(r'on\w+="goPage\(\'([\w-]+)\'\)', HTML):
            self.assertIn(f'id="page-{nav}"', HTML, f"nav target page-{nav} does not exist")


class TestDashboardScript(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.code = _strip_comments_and_strings(SCRIPT)
        cls.defined = set(re.findall(r"function\s+([A-Za-z_$][\w$]*)\s*\(", SCRIPT))
        cls.defined |= set(
            re.findall(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function", SCRIPT)
        )
        # Any declared variable may hold a callable: aliases used to wrap
        # functions (`const originalGoPage3 = goPage; goPage = function(id)...`).
        cls.defined |= set(re.findall(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=", SCRIPT))
        # Parameters of functions and arrow callbacks are callables too
        # (`new Promise((resolve) => ...)`, `.map((s, i) => ...)`).
        for params in re.findall(r"function\s*[A-Za-z_$][\w$]*\s*\(([^)]*)\)", SCRIPT):
            cls.defined |= set(re.findall(r"[A-Za-z_$][\w$]*", params))
        for params in re.findall(r"\(([^()]*)\)\s*=>", SCRIPT):
            cls.defined |= set(re.findall(r"[A-Za-z_$][\w$]*", params))
        cls.defined |= set(re.findall(r"([A-Za-z_$][\w$]*)\s*=>", SCRIPT))

    def test_no_python_constructs_in_browser_code(self):
        self.assertNotIn("new DetectionEngine", SCRIPT,
                         "the browser cannot instantiate the Python engine")

    def test_every_onclick_handler_is_defined(self):
        handlers = set(re.findall(r'on\w+="([A-Za-z_$][\w$]*)\s*\(', HTML))
        missing = sorted(h for h in handlers if h not in self.defined)
        self.assertEqual(missing, [], f"onclick handlers with no definition: {missing}")

    def test_no_called_but_undefined_functions(self):
        called = set(re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(", self.code))
        missing = sorted(
            n for n in called
            if n not in self.defined and n not in JS_BUILTINS
        )
        self.assertEqual(missing, [], f"functions called but never defined: {missing}")

    def test_progress_state_variables_are_declared(self):
        """wsProgress/currentScanId were read without ever being declared."""
        for name in ("wsProgress", "currentScanId"):
            self.assertRegex(
                SCRIPT, rf"\b(?:let|const|var)\s+{name}\b",
                f"{name} is used but never declared",
            )

    def test_folder_scan_helpers_exist(self):
        for fn in ("generateScanId", "connectProgressWS", "disconnectProgressWS",
                   "scanFolderHandle", "scanDirectoryHandle"):
            self.assertIn(fn, self.defined, f"{fn}() is required by folder drag-drop")


class TestDashboardStyles(unittest.TestCase):

    def test_modal_css_is_defined(self):
        """Without these rules every dialog rendered inline on every page."""
        for cls in ("modal-overlay", "modal", "modal-header", "modal-body",
                    "modal-footer", "modal-close"):
            self.assertRegex(
                CSS, rf"\.{cls}\b", f".{cls} is used in markup but has no CSS rule"
            )

    def test_modal_overlay_is_hidden_until_opened(self):
        block = re.search(r"\.modal-overlay\s*\{([^}]*)\}", CSS)
        self.assertIsNotNone(block, "no .modal-overlay rule")
        self.assertIn("display:none", block.group(1).replace(" ", ""))
        self.assertIn(".modal-overlay.open", CSS)


class TestFrontendBackendContract(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # FastAPI >= 0.141 wraps each include_router() call in a single
        # _IncludedRouter entry on app.routes, so sub-paths such as /projects
        # and /schedule are no longer listed there flatly. The generated
        # OpenAPI schema still walks every nested router (and no route in this
        # project is hidden with include_in_schema=False), so it is the
        # reliable source for "does this URL exist?".
        cls.routes = {
            re.sub(r"\{[^}]+\}", "X", path)
            for path in app.openapi().get("paths", {})
        }

    def _fetch_paths(self):
        paths = set()
        for raw in re.findall(r"fetch\(\s*[`'\"]([^`'\"]+)", SCRIPT):
            if not raw.startswith("/"):
                continue  # variable URLs, e.g. saveProject's `url`
            paths.add(re.sub(r"\$\{[^}]*\}", "X", raw).split("?")[0])
        return paths

    def test_every_fetch_path_matches_a_backend_route(self):
        missing = sorted(p for p in self._fetch_paths() if p not in self.routes)
        self.assertEqual(missing, [], f"frontend calls routes that do not exist: {missing}")

    def test_projects_page_does_not_use_the_legacy_api_prefix(self):
        self.assertNotIn("/api/projects", SCRIPT)


if __name__ == "__main__":
    unittest.main()


