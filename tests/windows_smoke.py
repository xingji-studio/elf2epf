"""Test native Windows CLI using sample ELF files and reference Linux EPF output.

Runs with Windows Python or with Python in WSL when Windows interop is available.
Build the two README examples first. Temporary files stay beside the executable.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def native_path(path):
    path = Path(path).resolve()
    if os.name == "nt":
        return str(path)
    parts = path.parts
    if len(parts) >= 4 and parts[1] == "mnt" and len(parts[2]) == 1:
        return parts[2].upper() + ":/" + "/".join(parts[3:])
    raise ValueError("WSL test paths must be on a mounted Windows drive")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", required=True)
    parser.add_argument("--fixtures", required=True)
    parser.add_argument("--profile", required=True)
    args = parser.parse_args()
    tool, fixtures = Path(args.tool).resolve(), Path(args.fixtures).resolve()

    def run(*arguments, expected=0):
        result = subprocess.run([str(tool), *map(str, arguments)], capture_output=True,
                                encoding="utf-8", errors="replace", timeout=15)
        assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)
        return result

    assert "0.1.0" in run("--version").stdout
    with tempfile.TemporaryDirectory(prefix="windows-smoke-", dir=tool.parent) as scratch:
        directory = Path(scratch) / "中文路径"
        directory.mkdir()
        for source, output, kind, extra in (
            ("minimal.elf", "minimal.epf", "exec", []),
            ("libmath.so", "libmath.eps", "shared", ["--soname", "libmath.eps"]),
        ):
            input_path = directory / ("输入-" + source)
            output_path = directory / ("输出-" + output)
            shutil.copyfile(fixtures / source, input_path)
            options = ["--type", kind, "--profile", native_path(args.profile), *extra]
            run("check", native_path(input_path), *options)
            assert not output_path.exists()
            run("convert", native_path(input_path), "-o", native_path(output_path), *options)
            run("verify", native_path(output_path), "--deps")
            assert "x86-64" in run("inspect", native_path(output_path)).stdout
            assert output_path.read_bytes() == (fixtures / output).read_bytes(), "Windows and Linux EPF bytes differ"
            result = run("convert", native_path(input_path), "-o", native_path(output_path), *options, expected=1)
            assert "already exists" in result.stderr
            assert output_path.read_bytes() == (fixtures / output).read_bytes()
        assert not list(directory.glob("*.tmp-*"))
    print("Windows native CLI: EXEC/SHARED, Unicode paths, output protection and Linux byte comparison passed.")


if __name__ == "__main__":
    main()
