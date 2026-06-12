# APK Extractor

A local web tool that extracts and analyses Android APK files — manifests, permissions, components, certificates, strings, DEX stats, and assets — served through a clean browser UI with a REST API.

## What it extracts

| Category | Details |
|---|---|
| **Manifest** | Package name, version, SDK range, application attributes |
| **Permissions** | All `uses-permission` entries, categorised as Dangerous / Normal / Custom |
| **Components** | Activities, Services, Broadcast Receivers, Content Providers |
| **Files** | Full file listing with sizes and download links |
| **DEX** | Per-file class, method, field, string counts |
| **Native libs** | `.so` files grouped by ABI |
| **Assets** | Everything under `/assets/` |
| **Certificates** | Subject, issuer, validity, SHA-256 fingerprint |
| **Strings** | Printable strings extracted from `resources.arsc` |

## Requirements

- Python 3.10+
- pip

## Setup

```bash
git clone https://github.com/pramodkhot/APK-Extractor.git
cd APK-Extractor
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Then open **http://localhost:5000** in your browser.

On Windows you can also double-click **`start.bat`**.

## Usage

1. Click or drag an `.apk` file onto the upload zone
2. Wait a few seconds for analysis to complete
3. Browse the tabs: Summary, Manifest, Permissions, Components, Files, DEX, Native Libs, Assets, Certificates, Strings
4. Click the **↓** button on any file row to download the extracted file

## REST API

All data is also available as JSON while the server is running:

| Endpoint | Description |
|---|---|
| `GET /api/apks` | List all analysed APKs |
| `POST /api/upload` | Upload an APK (field: `apk`) |
| `GET /api/apk/<id>/summary` | Basic info + counts |
| `GET /api/apk/<id>/manifest` | Parsed manifest |
| `GET /api/apk/<id>/permissions` | Permissions with categories |
| `GET /api/apk/<id>/components` | Activities, services, receivers, providers |
| `GET /api/apk/<id>/files` | Full file list (supports `?q=filter`) |
| `GET /api/apk/<id>/dex` | DEX header stats |
| `GET /api/apk/<id>/native-libs` | Native libraries |
| `GET /api/apk/<id>/assets` | Asset files |
| `GET /api/apk/<id>/certificates` | Signing certificates |
| `GET /api/apk/<id>/strings` | Extracted strings (supports `?q=filter&limit=N`) |
| `GET /api/apk/<id>/full` | Complete analysis JSON |
| `GET /api/apk/<id>/download?path=...` | Download an extracted file |
| `DELETE /api/apk/<id>` | Delete an analysis |

### Example — upload via curl

```bash
curl -X POST http://localhost:5000/api/upload \
     -F "apk=@MyApp.apk"
```

### Example — read data in Python

```python
import json, requests

# Upload
with open('MyApp.apk', 'rb') as f:
    r = requests.post('http://localhost:5000/api/upload', files={'apk': f})
apk_id = r.json()['id']

# Read permissions
perms = requests.get(f'http://localhost:5000/api/apk/{apk_id}/permissions').json()
print(perms['categorized']['dangerous'])
```

## Data storage

Each analysed APK is saved in `workspace/<uuid>/`:

```
workspace/
└── <uuid>/
    ├── analysis.json     ← all extracted data
    └── extracted/        ← full APK contents (unzipped)
```

The `workspace/` folder is excluded from git (see `.gitignore`).

## Project layout

```
APK-Extractor/
├── app.py              Flask server + REST API
├── apk_analyzer.py     Core extraction logic
├── axml_parser.py      Binary AndroidManifest.xml parser
├── templates/
│   └── index.html      Single-page web UI
├── requirements.txt
└── start.bat           Windows launcher
```

## Limitations

- APK signing block v2/v3 certificates are not parsed (only v1 / META-INF/*.RSA)
- Resources (images, drawables) are not decoded — only listed
- No DEX decompilation (class/method counts only)

## License

MIT
