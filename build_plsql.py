"""
Build tree_sitter_plsql Python extension from a cloned tree-sitter-plsql grammar.

Usage:
    python build_plsql.py /path/to/tree-sitter-plsql

The script compiles src/parser.c into a Python C extension and installs it
into the current environment so `import tree_sitter_plsql` works.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

BINDING_C = """\
#include <Python.h>
#include "tree_sitter/parser.h"

typedef struct TSLanguage TSLanguage;
extern TSLanguage *tree_sitter_plsql(void);

static PyObject *
_language(PyObject *Py_UNUSED(self), PyObject *Py_UNUSED(args))
{
    return PyCapsule_New(tree_sitter_plsql(), "tree_sitter.Language", NULL);
}

static PyMethodDef methods[] = {
    {"language", _language, METH_NOARGS, "Return the PL/SQL tree-sitter language."},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef mod = {
    PyModuleDef_HEAD_INIT, "tree_sitter_plsql", NULL, -1, methods,
};

PyMODINIT_FUNC
PyInit_tree_sitter_plsql(void)
{
    return PyModule_Create(&mod);
}
"""

SETUP_PY = """\
from setuptools import setup, Extension
import sys

setup(
    name="tree-sitter-plsql",
    version="0.0.1",
    ext_modules=[
        Extension(
            "tree_sitter_plsql",
            sources=["src/parser.c", "binding.c"],
            include_dirs=["src"],
            extra_compile_args=["-std=c11"] if sys.platform != "win32" else [],
        )
    ],
)
"""


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python build_plsql.py /path/to/tree-sitter-plsql")
        sys.exit(1)

    grammar_dir = Path(sys.argv[1]).resolve()
    parser_c = grammar_dir / "src" / "parser.c"

    if not parser_c.exists():
        # Try generating from grammar.js via tree-sitter CLI
        print("src/parser.c not found — attempting tree-sitter generate ...")
        result = subprocess.run(
            ["tree-sitter", "generate"],
            cwd=grammar_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0 or not parser_c.exists():
            print("ERROR: Could not find or generate src/parser.c")
            print(result.stderr)
            sys.exit(1)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # Copy src/ into build directory
        shutil.copytree(grammar_dir / "src", tmp_path / "src")

        # Write binding and setup
        (tmp_path / "binding.c").write_text(BINDING_C)
        (tmp_path / "setup.py").write_text(SETUP_PY)

        print(f"Building tree_sitter_plsql from {grammar_dir} ...")
        result = subprocess.run(
            [sys.executable, "setup.py", "build_ext", "--inplace"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print("Build failed:")
            print(result.stdout)
            print(result.stderr)
            sys.exit(1)

        # Find the compiled .so / .pyd
        so_files = list(tmp_path.glob("tree_sitter_plsql*.so")) + \
                   list(tmp_path.glob("tree_sitter_plsql*.pyd"))
        if not so_files:
            print("ERROR: compiled extension not found after build")
            sys.exit(1)

        # Install into site-packages via pip
        print("Installing ...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-build-isolation", "."],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print("Install failed:")
            print(result.stdout)
            print(result.stderr)
            sys.exit(1)

    print("Done. Verify with: python -c \"import tree_sitter_plsql; print(tree_sitter_plsql.language())\"")


if __name__ == "__main__":
    main()
