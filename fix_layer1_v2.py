with open('scripts/layer1_static_analysis.py', encoding='utf-8') as f:
    lines = f.readlines()

# Find the line with run_codeql_analysis definition
start = None
for i, line in enumerate(lines):
    if 'def run_codeql_analysis(' in line:
        start = i
        break

if start is None:
    print("ERROR: function not found")
else:
    # Replace from the function definition line onwards
    # Insert early return after the function signature line
    new_lines = (
        lines[:start] +
        ['def run_codeql_analysis(repo_path: str, language: str, db_path: str) -> list[dict]:\n',
         '    print("[Layer 1] CodeQL skipped - not installed in CI")\n',
         '    return []\n',
         '\n',
         '\n',
         'def run_codeql_disabled(repo_path: str, language: str, db_path: str) -> list[dict]:\n'] +
        lines[start+1:]  # keep the rest of the old function (it becomes disabled)
    )
    with open('scripts/layer1_static_analysis.py', 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    print(f"SUCCESS: Patched at line {start+1}")
    # Show result
    for i, l in enumerate(new_lines[start:start+8], start+1):
        print(f"{i}: {l}", end='')
