import pathlib, re

for fpath in ["/app/sonar-ai/api.py", "/app/fortify-ai/api_server.py"]:
    p = pathlib.Path(fpath)
    if not p.exists():
        print(f"Skipping (not found): {fpath}")
        continue
    txt = p.read_text()
    txt = re.sub(
        r'app\.add_middleware\s*\(\s*CORSMiddleware.*?\)',
        'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])',
        txt,
        flags=re.DOTALL
    )
    p.write_text(txt)
    print(f"Patched CORS: {fpath}")
