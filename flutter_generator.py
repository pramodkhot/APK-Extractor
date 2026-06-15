"""
Generate a Flutter project from an analysed APK workspace.

Strategy:
  - Clone C:\\Projects\\AshtavakraGita as the template (same theme, same structure)
  - Swap in the workspace's extracted JSON data + images
  - Patch all text files (names, package IDs, versions, counts)
  - Save the result to C:\\Projects\\<AppName>
"""

import json
import os
import re
import shutil
from pathlib import Path

from dex_extractor import build_chapter_json, extract_content_strings

# ── Config ─────────────────────────────────────────────────────────────────────

TEMPLATE_DIR  = Path(r"C:\Projects\AshtavakraGita")
OUTPUT_BASE   = Path(r"C:\Projects")

# String values that exist in the template and must be replaced
TMPL_APP_ID    = "com.creative.ashtavakra_gita"
TMPL_DART_PKG  = "ashtavakra_gita"
TMPL_APP_NAME  = "Ashtavakra Gita"
TMPL_APP_HINDI = "अष्टावक्र गीता"
TMPL_SUBTITLE  = "The Song of the Self"
TMPL_IMAGE     = "ast_img.jpeg"
TMPL_FOLDER    = "AshtavakraGita"   # used in build.yml artifact names
TMPL_VERSION   = "1.0.0+1"

# File extensions we do text replacement on
TEXT_EXTS = {
    ".dart", ".yaml", ".yml", ".kts", ".gradle",
    ".xml", ".md", ".properties", ".txt",
}

# Directories inside the template we never copy
COPY_IGNORE = shutil.ignore_patterns(
    ".dart_tool", ".idea", "build", "*.iml",
    ".flutter-plugins", ".flutter-plugins-dependencies",
    ".packages", ".pub-cache", "pubspec.lock",
)

# Directories inside the output we skip during text patching
PATCH_SKIP_DIRS = {"assets", "build", ".git", ".dart_tool"}


# ── Public entry point ─────────────────────────────────────────────────────────

def generate_flutter_project(workspace_path: str, analysis: dict) -> dict:
    """
    Generate a Flutter project from a workspace.

    Returns:
        {
          "path":     absolute path to the generated project,
          "app_name": human-readable name,
          "pattern":  "ashtavakra" | "chapters_only" | "none",
          "chapters": int,
          "items":    int,
        }
    """
    gen = _Generator(Path(workspace_path), analysis)
    return gen.run()


# ── Generator class ────────────────────────────────────────────────────────────

class _Generator:
    def __init__(self, workspace: Path, analysis: dict):
        self.workspace = workspace
        self.analysis  = analysis
        self.extracted = workspace / "extracted"

    def run(self) -> dict:
        meta = self._extract_meta()
        data = self._detect_data()

        if data.get("level", 0) == 0:
            return {
                "blocked":     True,
                "level":       0,
                "level_label": "Server-side Data",
                "app_name":    meta["app_name"],
                "message": (
                    f"'{meta['app_name']}' loads its content from a remote server — "
                    "no extractable data found in this APK (no JSON assets, no readable DEX strings). "
                    "Please choose an APK with embedded data."
                ),
            }

        image = self._find_app_image()

        out_dir = _unique_output_dir(meta["folder_name"])

        self._copy_template(out_dir)
        self._copy_data_assets(out_dir, data)
        self._copy_app_image(out_dir, image, meta)
        self._patch_text_files(out_dir, meta, data)
        self._patch_home_screen(out_dir, meta, data)
        self._patch_build_gradle(out_dir, meta)   # explicit regex — reliable on all systems

        return {
            "path":        str(out_dir),
            "app_name":    meta["app_name"],
            "pattern":     data["pattern"],
            "level":       data.get("level", 0),
            "level_label": data.get("level_label", "Server-side Data"),
            "chapters":    data.get("chapter_count", 0),
            "items":       data.get("total_items", 0),
        }

    # ── Metadata ──────────────────────────────────────────────────────────────

    def _extract_meta(self) -> dict:
        manifest = self.analysis.get("manifest", {})
        pkg = manifest.get("package", "") or ""

        # App display name: try manifest application label first
        app_attrs = manifest.get("application", {})
        label = ""
        if isinstance(app_attrs, dict):
            label = app_attrs.get("label", "") or ""
        if label.startswith("@"):   # resource ref, not a string
            label = ""

        if label:
            app_name = label.strip()
        elif pkg:
            last = pkg.split(".")[-1]
            last = _split_camel(last)        # "ShriSatyanarayankatha" → "Shri Satyanarayankatha"
            app_name = last.replace("_", " ").title()
        else:
            stem = re.sub(r"_v[\d.]+$", "", self.workspace.name)
            stem = _split_camel(stem)
            app_name = stem.replace("_", " ").title()

        version_name = manifest.get("versionName", "") or "1.0.0"
        version_code = str(manifest.get("versionCode", "") or "1")

        dart_pkg    = _to_dart_pkg(app_name)
        folder_name = _to_pascal(app_name)
        app_id      = f"com.creative.{dart_pkg}"

        return {
            "app_name":     app_name,
            "dart_pkg":     dart_pkg,
            "folder_name":  folder_name,
            "app_id":       app_id,
            "version":      f"{version_name}+{version_code}",
            "version_name": version_name,
            "image_name":   TMPL_IMAGE,   # updated later if image is found
        }

    # ── Data detection ────────────────────────────────────────────────────────

    def _detect_data(self) -> dict:
        # Level 1 — JSON assets (Flutter data pattern)
        search_roots = [
            self.extracted / "assets" / "flutter_assets" / "assets" / "database",
            self.extracted / "assets" / "flutter_assets" / "assets",
            self.extracted / "assets",
        ]
        for base in search_roots:
            if not base.exists():
                continue
            result = self._try_parse(base)
            if result:
                result["level"] = 1
                result["level_label"] = "Level 1 — JSON"
                return result

        # Level 2 — DEX string pool extraction
        dex_result = self._try_dex_extract()
        if dex_result:
            return dex_result

        # No extractable data (server-side / hardcoded)
        return {"pattern": "none", "level": 0, "level_label": "Server-side Data", "source_dir": None}

    def _try_dex_extract(self) -> dict:
        dex_files = sorted(self.extracted.glob("classes*.dex"))
        if not dex_files:
            return None

        seen = set()
        all_strings = []
        for dex in dex_files:
            for s in extract_content_strings(dex):
                if s not in seen:
                    seen.add(s)
                    all_strings.append(s)
            if len(all_strings) >= 800:
                break

        if not all_strings:
            return None

        # Non-ASCII (Devanagari/regional script) first, then by length descending
        all_strings.sort(key=lambda s: (not any(ord(c) > 127 for c in s), -len(s)))
        all_strings = all_strings[:300]

        contains, chapter = build_chapter_json(all_strings)

        return {
            "pattern":       "dex",
            "level":         2,
            "level_label":   "Level 2 — DEX Extract",
            "dex_contains":  contains,
            "dex_chapter":   chapter,
            "chapter_count": 1,
            "total_items":   len(all_strings),
            "source_dir":    None,
        }

    def _try_parse(self, base: Path):
        contains  = base / "contains.json"
        chapters  = sorted(base.glob("chapter*.json"),
                           key=lambda p: _chapter_num(p.name))

        if contains.exists() and chapters:
            total = sum(_count_items(c) for c in chapters)
            return {
                "pattern":       "ashtavakra",
                "source_dir":    base,
                "contains_file": contains,
                "chapter_files": chapters,
                "chapter_count": len(chapters),
                "total_items":   total,
            }

        if chapters:
            total = sum(_count_items(c) for c in chapters)
            return {
                "pattern":       "chapters_only",
                "source_dir":    base,
                "contains_file": None,
                "chapter_files": chapters,
                "chapter_count": len(chapters),
                "total_items":   total,
            }

        return None

    # ── Image detection ───────────────────────────────────────────────────────

    def _find_app_image(self):
        # Priority 1: flutter_assets images folder (same path as original)
        flutter_imgs = (
            self.extracted / "assets" / "flutter_assets" / "assets" / "images"
        )
        if flutter_imgs.exists():
            for pat in ("*.jpeg", "*.jpg", "*.png", "*.webp"):
                found = list(flutter_imgs.glob(pat))
                if found:
                    return found[0]

        # Priority 2: best mipmap foreground icon (large, high quality)
        for mipmap in ("mipmap-xxxhdpi-v4", "mipmap-xxxhdpi"):
            p = self.extracted / "res" / mipmap / "ic_launcher_foreground.png"
            if p.exists():
                return p

        # Priority 3: any launcher icon
        for mipmap in ("mipmap-xxxhdpi-v4", "mipmap-xxxhdpi",
                       "mipmap-xxhdpi-v4", "mipmap-xxhdpi"):
            p = self.extracted / "res" / mipmap / "ic_launcher.png"
            if p.exists():
                return p

        return None

    # ── Copy operations ───────────────────────────────────────────────────────

    def _copy_template(self, out_dir: Path):
        shutil.copytree(str(TEMPLATE_DIR), str(out_dir), ignore=COPY_IGNORE)

    def _copy_data_assets(self, out_dir: Path, data: dict):
        if data["pattern"] == "none":
            return  # keep template data as-is

        db_dir = out_dir / "assets" / "database"

        # Remove existing template JSON files
        for f in db_dir.glob("*.json"):
            f.unlink()

        if data["pattern"] == "dex":
            # Write DEX-extracted strings as chapter1.json + contains.json
            (db_dir / "contains.json").write_text(
                json.dumps(data["dex_contains"], ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (db_dir / "chapter1.json").write_text(
                json.dumps(data["dex_chapter"], ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            return

        # JSON pattern (ashtavakra / chapters_only): copy source files
        for chap_file in data.get("chapter_files", []):
            shutil.copy2(chap_file, db_dir / chap_file.name)

        if data.get("contains_file") and data["contains_file"].exists():
            shutil.copy2(data["contains_file"], db_dir / "contains.json")
        else:
            items = [
                {"id": i + 1, "subtitle": f"Part {i + 1}"}
                for i in range(data["chapter_count"])
            ]
            (db_dir / "contains.json").write_text(
                json.dumps({"items": items}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

    def _copy_app_image(self, out_dir: Path, image, meta: dict):
        if image is None:
            return  # keep ast_img.jpeg

        images_dir = out_dir / "assets" / "images"
        ext        = image.suffix.lower()
        img_name   = _to_dart_pkg(meta["app_name"]) + ext
        dest       = images_dir / img_name

        shutil.copy2(image, dest)

        # Remove old template image if it's a different file
        old_img = images_dir / TMPL_IMAGE
        if dest.resolve() != old_img.resolve() and old_img.exists():
            old_img.unlink()

        meta["image_name"] = img_name

    # ── Text patching ─────────────────────────────────────────────────────────

    def _patch_text_files(self, out_dir: Path, meta: dict, data: dict):
        replacements = [
            # Most specific first to avoid partial matches
            (TMPL_APP_ID,    meta["app_id"]),
            (TMPL_DART_PKG,  meta["dart_pkg"]),
            (TMPL_APP_HINDI, meta["app_name"]),
            (TMPL_APP_NAME,  meta["app_name"]),
            (TMPL_SUBTITLE,  f"Explore {meta['app_name']}"),
            (TMPL_IMAGE,     meta["image_name"]),
            (TMPL_FOLDER,    meta["folder_name"]),
            (TMPL_VERSION,   meta["version"]),
            # Version string in settings screen
            ("'Version 1.0.0'", f"'Version {meta['version_name']}'"),
        ]

        for root, dirs, files in os.walk(out_dir):
            dirs[:] = [d for d in dirs if d not in PATCH_SKIP_DIRS]
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() not in TEXT_EXTS:
                    continue
                _patch_file(fpath, replacements)

    def _patch_build_gradle(self, out_dir: Path, meta: dict):
        """Directly overwrite namespace/applicationId with regex — bypasses any encoding issue."""
        gradle = out_dir / "android" / "app" / "build.gradle.kts"
        if not gradle.exists():
            return
        text = gradle.read_text(encoding="utf-8")
        text = re.sub(r'namespace\s*=\s*"[^"]*"',      f'namespace = "{meta["app_id"]}"',      text)
        text = re.sub(r'applicationId\s*=\s*"[^"]*"',  f'applicationId = "{meta["app_id"]}"',  text)
        gradle.write_text(text, encoding="utf-8")

    def _patch_home_screen(self, out_dir: Path, meta: dict, data: dict):
        screen = out_dir / "lib" / "screens" / "home_screen.dart"
        if not screen.exists():
            return

        text = screen.read_text(encoding="utf-8")

        # Update chapter / item counts in the stats row
        chap_count  = str(data.get("chapter_count", 20))
        total_items = str(data.get("total_items",   298))
        text = re.sub(
            r"_Stat\('[^']*',\s*'Chapters'\)",
            f"_Stat('{chap_count}', 'Chapters')",
            text,
        )
        text = re.sub(
            r"_Stat\('[^']*',\s*'Shlokas'\)",
            f"_Stat('{total_items}', 'Items')",
            text,
        )

        # Replace the hardcoded about paragraph
        about_pattern = re.compile(
            r"'The Ashtavakra Gita is.*?ultimate reality\.'",
            re.DOTALL,
        )
        name = meta["app_name"]
        about_replacement = (
            f"'{name} — explore the full content "
            "extracted and packaged for reading on any device.'"
        )
        text = about_pattern.sub(about_replacement, text)

        screen.write_text(text, encoding="utf-8")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _split_camel(name: str) -> str:
    """Insert spaces between CamelCase words: 'ShriKatha' → 'Shri Katha'."""
    return re.sub(r'(?<=[a-z])([A-Z])', r' \1', name)


def _to_dart_pkg(name: str) -> str:
    """Convert any string to a valid Dart package name (snake_case, lowercase)."""
    s = re.sub(r"[^\w\s]", "", name)
    s = re.sub(r"\s+", "_", s.strip())
    s = s.lower()
    s = re.sub(r"_+", "_", s).strip("_")
    # Must start with a letter
    if s and s[0].isdigit():
        s = "app_" + s
    return s or "generated_app"


def _to_pascal(name: str) -> str:
    """Convert any string to PascalCase folder name."""
    words = re.sub(r"[^\w\s]", "", name).split()
    return "".join(w.title() for w in words) or "GeneratedApp"


def _chapter_num(filename: str) -> int:
    """Extract numeric sort key from 'chapter3.json' → 3."""
    m = re.search(r"(\d+)", filename)
    return int(m.group(1)) if m else 0


def _count_items(json_path: Path) -> int:
    try:
        data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
        return len(data.get("items", []))
    except Exception:
        return 0


def _unique_output_dir(folder_name: str) -> Path:
    out = OUTPUT_BASE / folder_name
    if not out.exists():
        return out
    i = 2
    while (OUTPUT_BASE / f"{folder_name}_{i}").exists():
        i += 1
    return OUTPUT_BASE / f"{folder_name}_{i}"


def _patch_file(path: Path, replacements: list):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        patched = text
        for old, new in replacements:
            patched = patched.replace(old, new)
        if patched != text:
            path.write_text(patched, encoding="utf-8")
    except Exception:
        pass
