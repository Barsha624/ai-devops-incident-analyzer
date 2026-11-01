from __future__ import annotations

import html
import json
import re
import subprocess
import tempfile
from pathlib import Path

import markdown
from  import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT = DOCS / "ai-devops-incident-analyzer-guide.pdf"

PARTS = [
    (
        "Part 1 - The project explained",
        ["project-walkthrough.md", "why-deterministic-first.md", "architecture.md"],
    ),
    ("Part 2 - The rules", ["detection-rules.md", "severity.md", "grouping.md"]),
    (
        "Part 3 - Optional AI, privacy and operations",
        ["ai-explanations.md", "security-privacy.md", "monitoring.md"],
    ),
    ("Part 4 - Interview preparation", ["interview-guide.md", "limitations.md"]),
]

MERMAID = re.compile(r"```mermaid\n(.*?)```", re.S)


def render_mermaid(source: str, workdir: Path, index: int) -> str:
    src, png = workdir / f"d{index}.mmd", workdir / f"d{index}.png"
    cfg = workdir / "pp.json"
    cfg.write_text(json.dumps({"args": ["--no-sandbox"]}))
    src.write_text(source)
    subprocess.run(
        ["mmdc", "-i", str(src), "-o", str(png), "-p", str(cfg), "-b", "white", "-s", "2"],
        check=True,
        capture_output=True,
    )
    return f'<p><img src="file://{png}" alt="diagram {index}"></p>'


def convert(text: str, workdir: Path, counter: list[int]) -> str:
    def swap(match: re.Match[str]) -> str:
        counter[0] += 1
        try:
            return "\n\n" + render_mermaid(match.group(1), workdir, counter[0]) + "\n\n"
        except (subprocess.CalledProcessError, FileNotFoundError):
            return f"\n\n<pre><code>{html.escape(match.group(1))}</code></pre>\n\n"

    text = MERMAID.sub(swap, text)
    return markdown.markdown(text, extensions=["tables", "fenced_code", "sane_lists"])


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        counter = [0]
        body = [
            '<div class="cover"><h1>ai-devops-incident-analyzer</h1>'
            "<h2>Project guide and interview preparation</h2>"
            '<p class="note">Deterministic log analysis, explainable severity, optional guard-railed AI.<br>'
            "All sample data in this project is synthetic. No accuracy or production claims are made.</p></div>"
        ]
        for title, files in PARTS:
            body.append(f'<h1 class="part">{html.escape(title)}</h1>')
            for name in files:
                body.append(convert((DOCS / name).read_text(encoding="utf-8"), work, counter))
        page = f"<html><head><meta charset='utf-8'><style>{CSS}</style></head><body>{''.join(body)}</body></html>"
        page_file = work / "guide.html"
        page_file.write_text(page, encoding="utf-8")
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            tab = browser.new_page()
            tab.goto(f"file://{page_file}")
            tab.pdf(
                path=str(OUT),
                format="A4",
                print_background=True,
                display_header_footer=True,
                header_template="<span></span>",
                footer_template=(
                    "<div style='font-size:8px;width:100%;text-align:center;color:#666'>"
                    "ai-devops-incident-analyzer guide - page <span class='pageNumber'></span>"
                    " / <span class='totalPages'></span></div>"
                ),
                margin={"top": "18mm", "bottom": "20mm", "left": "16mm", "right": "16mm"},
            )
            browser.close()
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
