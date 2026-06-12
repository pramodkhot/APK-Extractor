"""
APK Extractor — localhost Flask server.
Run:  python app.py
Then open http://localhost:5000
"""
import os
import tempfile
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file, abort
from flask_cors import CORS

from apk_analyzer import (
    analyze_apk,
    delete_apk,
    get_extracted_file,
    list_apks,
    load_analysis,
)

app = Flask(__name__)
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB max upload
app.jinja_env.auto_reload = True  # always serve fresh templates


# ──────────────────────────────────────────────────────────────────────────────
# Web UI
# ──────────────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


# ──────────────────────────────────────────────────────────────────────────────
# API — APK list & upload
# ──────────────────────────────────────────────────────────────────────────────

@app.route('/api/apks', methods=['GET'])
def api_list_apks():
    return jsonify(list_apks())


@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'apk' not in request.files:
        return jsonify({'error': 'No file field named "apk"'}), 400

    f = request.files['apk']
    if not f.filename:
        return jsonify({'error': 'Empty filename'}), 400
    if not f.filename.lower().endswith('.apk'):
        return jsonify({'error': 'File must have .apk extension'}), 400

    with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as tmp:
        tmp_path = Path(tmp.name)
        f.save(tmp_path)
        try:
            tmp_path = tmp_path.rename(tmp_path.parent / f.filename)
        except Exception:
            pass  # keep the tmp name if rename fails (e.g. name collision)

    try:
        result = analyze_apk(tmp_path)
    except Exception as e:
        import traceback
        return jsonify({'error': f'Analysis failed: {e}', 'trace': traceback.format_exc()}), 500
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass

    if result.get('errors'):
        result['_warnings'] = result.pop('errors')
    return jsonify(result), 201


# ──────────────────────────────────────────────────────────────────────────────
# API — per-APK data
# ──────────────────────────────────────────────────────────────────────────────

def _get_or_404(apk_id: str) -> dict:
    data = load_analysis(apk_id)
    if data is None:
        abort(404, description=f'APK {apk_id!r} not found')
    return data


@app.route('/api/apk/<apk_id>/summary')
def api_summary(apk_id):
    data = _get_or_404(apk_id)
    manifest = data.get('manifest', {})
    return jsonify({
        'id':           data['id'],
        'filename':     data['filename'],
        'fileSize':     data['fileSize'],
        'fileSizeHuman': data['fileSizeHuman'],
        'sha256':       data['sha256'],
        'md5':          data['md5'],
        'analyzedAt':   data['analyzedAt'],
        'package':      manifest.get('package', ''),
        'versionCode':  manifest.get('versionCode', ''),
        'versionName':  manifest.get('versionName', ''),
        'minSdkVersion':    manifest.get('minSdkVersion', ''),
        'targetSdkVersion': manifest.get('targetSdkVersion', ''),
        'permissionCount':  len(data.get('permissions', [])),
        'activityCount':    len(data.get('components', {}).get('activities', [])),
        'serviceCount':     len(data.get('components', {}).get('services', [])),
        'receiverCount':    len(data.get('components', {}).get('receivers', [])),
        'providerCount':    len(data.get('components', {}).get('providers', [])),
        'dexCount':         len(data.get('dex', [])),
        'nativeLibCount':   len(data.get('nativeLibs', [])),
        'assetCount':       len(data.get('assets', [])),
        'fileCount':        len(data.get('files', [])),
        'certCount':        len(data.get('certificates', [])),
        'warnings':         data.get('_warnings', []),
    })


@app.route('/api/apk/<apk_id>/manifest')
def api_manifest(apk_id):
    data = _get_or_404(apk_id)
    return jsonify(data.get('manifest', {}))


@app.route('/api/apk/<apk_id>/permissions')
def api_permissions(apk_id):
    data = _get_or_404(apk_id)
    perms = data.get('permissions', [])
    categorized = _categorize_permissions(perms)
    return jsonify({'permissions': perms, 'categorized': categorized, 'count': len(perms)})


@app.route('/api/apk/<apk_id>/components')
def api_components(apk_id):
    data = _get_or_404(apk_id)
    return jsonify(data.get('components', {}))


@app.route('/api/apk/<apk_id>/files')
def api_files(apk_id):
    data = _get_or_404(apk_id)
    files = data.get('files', [])
    # optional filter
    q = request.args.get('q', '').lower()
    if q:
        files = [f for f in files if q in f['path'].lower()]
    return jsonify({'files': files, 'count': len(files)})


@app.route('/api/apk/<apk_id>/dex')
def api_dex(apk_id):
    data = _get_or_404(apk_id)
    return jsonify(data.get('dex', []))


@app.route('/api/apk/<apk_id>/native-libs')
def api_native_libs(apk_id):
    data = _get_or_404(apk_id)
    return jsonify(data.get('nativeLibs', []))


@app.route('/api/apk/<apk_id>/assets')
def api_assets(apk_id):
    data = _get_or_404(apk_id)
    return jsonify(data.get('assets', []))


@app.route('/api/apk/<apk_id>/certificates')
def api_certificates(apk_id):
    data = _get_or_404(apk_id)
    return jsonify(data.get('certificates', []))


@app.route('/api/apk/<apk_id>/strings')
def api_strings(apk_id):
    data = _get_or_404(apk_id)
    strings = data.get('strings', [])
    q = request.args.get('q', '').lower()
    if q:
        strings = [s for s in strings if q in s.lower()]
    limit = int(request.args.get('limit', 500))
    return jsonify({'strings': strings[:limit], 'total': len(strings)})


@app.route('/api/apk/<apk_id>/full')
def api_full(apk_id):
    """Return the complete analysis JSON."""
    data = _get_or_404(apk_id)
    return jsonify(data)


@app.route('/api/apk/<apk_id>/download')
def api_download(apk_id):
    """Download a specific extracted file. ?path=relative/path/in/apk"""
    _get_or_404(apk_id)
    file_path = request.args.get('path', '')
    if not file_path:
        abort(400, description='path query param required')
    target = get_extracted_file(apk_id, file_path)
    if target is None:
        abort(404, description='File not found in extracted APK')
    return send_file(target, as_attachment=True, download_name=target.name)


@app.route('/api/apk/<apk_id>', methods=['DELETE'])
def api_delete(apk_id):
    if delete_apk(apk_id):
        return jsonify({'deleted': apk_id})
    abort(404, description=f'APK {apk_id!r} not found')


# ──────────────────────────────────────────────────────────────────────────────
# Permission categorizer (best-effort)
# ──────────────────────────────────────────────────────────────────────────────

_DANGER_KEYWORDS = [
    'CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS', 'WRITE_CONTACTS',
    'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'READ_CALL_LOG',
    'WRITE_CALL_LOG', 'PROCESS_OUTGOING_CALLS', 'READ_SMS', 'RECEIVE_SMS',
    'SEND_SMS', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
    'READ_PHONE_STATE', 'CALL_PHONE', 'GET_ACCOUNTS', 'USE_BIOMETRIC',
    'BODY_SENSORS', 'ACTIVITY_RECOGNITION',
]

def _categorize_permissions(perms: list[str]) -> dict:
    dangerous, normal, custom = [], [], []
    for p in perms:
        short = p.split('.')[-1]
        if short in _DANGER_KEYWORDS:
            dangerous.append(p)
        elif '.' not in p or p.startswith('android.permission.'):
            normal.append(p)
        else:
            custom.append(p)
    return {'dangerous': dangerous, 'normal': normal, 'custom': custom}


# ──────────────────────────────────────────────────────────────────────────────
# Error handlers
# ──────────────────────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': str(e)}), 404

@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': str(e)}), 400

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large (max 500 MB)'}), 413


# ──────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f'\n  APK Extractor running at  http://localhost:{port}\n')
    app.run(host='0.0.0.0', port=port, debug=False)
