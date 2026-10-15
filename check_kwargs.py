"""Lists every keyword the tests pass to SecurityEvent(...) and whether the
model accepts it. Run from the repo root:  python check_kwargs.py
"""
import ast
import dataclasses
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from backend.app.decision.models import SecurityEvent  # noqa: E402

TEST_DIR = pathlib.Path("backend/tests/unit")
model_fields = [f.name for f in dataclasses.fields(SecurityEvent)]

seen = {}  # keyword -> example value
for path in sorted(TEST_DIR.glob("test_*.py")):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", getattr(node.func, "attr", "")) == "SecurityEvent"
        ):
            for kw in node.keywords:
                if kw.arg:
                    seen.setdefault(kw.arg, (path.name, node.lineno, ast.unparse(kw.value)))

print("SecurityEvent model fields:", model_fields)
print()
print(f"{'keyword':<18}{'in model?':<11}example (file:line = value)")
print("-" * 70)
for name, (fname, line, value) in seen.items():
    ok = "yes" if name in model_fields else "MISSING"
    print(f"{name:<18}{ok:<11}{fname}:{line} = {value}")
