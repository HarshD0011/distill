"""Analyze language fixtures and approval labels; never execute candidate commands."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def main(binary: str) -> None:
    binary = str(Path(binary).resolve())
    failures = []
    checks = 0
    timings = []
    unchecked = object()

    with tempfile.TemporaryDirectory(prefix="distill-language-tests-") as folder:
        root = Path(folder)
        key = root / "label.key"
        key.write_bytes(os.urandom(32))
        key.chmod(0o600)
        config = root / "policy.toml"
        config.write_text(f'[ledger]\nenabled=false\n[security]\nlabel_key_path="{key}"\n')
        analysis_env = dict(os.environ, HOME=str(root / "fake-home"))

        def fixture(name: str, source: str) -> str:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
            return shlex.quote(str(path))

        def check(name: str, command: str, severity: str, rule: str | None = None, *, impact=unchecked) -> None:
            nonlocal checks
            checks += 1
            report = json.loads(subprocess.check_output([
                binary, "analyze", "--config", str(config), "--cwd", folder, "--command", command
            ], env=analysis_env))
            timings.append(report["timings_ms"]["total"])
            event = {
                "hook_event_name": "PreToolUse",
                "cwd": folder,
                "tool_name": "Bash",
                "tool_input": {
                    "command": command,
                    "sandbox_permissions": "use_default",
                    "justification": "Language approval regression test",
                },
            }
            response = json.loads(subprocess.check_output(
                [binary, "hook", "codex", "--config", str(config), "--mode", "advisory", "--label-command"],
                input=json.dumps(event).encode(),
                env=analysis_env,
            ))
            rewrite = response.get("hookSpecificOutput", {})
            updated = rewrite.get("updatedInput", {})
            first, _, original = updated.get("command", "").partition("\n")
            if report["severity"] != severity:
                failures.append(f"{name}: expected {severity}, got {report['severity']}")
            if rule and not any(finding["rule_id"] == rule for finding in report["findings"]):
                failures.append(f"{name}: missing {rule} finding")
            if rule and severity == "critical" and not any(
                finding["rule_id"] == rule and finding["severity"] == "critical"
                for finding in report["findings"]
            ):
                failures.append(f"{name}: critical finding was lost during aggregation")
            if rule and rule.startswith("source.") and not any(
                evidence["source"] == "source_syntax"
                for finding in report["findings"] if finding["rule_id"] == rule
                for evidence in finding["evidence"]
            ):
                failures.append(f"{name}: missing source syntax evidence")
            if impact is not unchecked and report["impact_severity"] != impact:
                failures.append(f"{name}: expected impact {impact}, got {report['impact_severity']}")
            label = report["impact_severity"] or "unknown"
            color = {"unknown": "⚪", "safe": "🟢", "low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}[label]
            if not first.startswith(f"# Distill severity: {label.upper()} {color}"):
                failures.append(f"{name}: unexpected approval label {first!r}")
            coverage = report["coverage"]["summary"]
            if "| Analysis: " not in first:
                failures.append(f"{name}: approval label omits analysis coverage")
            if coverage != "static_accounted" and f"| Approval risk: {severity.upper()}" not in first:
                failures.append(f"{name}: incomplete label omits conservative approval risk")
            if coverage != "static_accounted" and report["decision"] == "allow":
                failures.append(f"{name}: incomplete analysis was allowed")
            if original != command:
                failures.append(f"{name}: hook changed executable command text")
            for key in ["sandbox_permissions", "justification"]:
                if updated.get(key) != event["tool_input"][key]:
                    failures.append(f"{name}: hook lost {key}")
            if rewrite.get("permissionDecision") != "allow":
                failures.append(f"{name}: missing PreToolUse rewrite decision")

        check("shell print", "printf '%s\\n' hello", "safe")
        check("curl version", "curl --version", "safe")
        check("macOS uname query", "uname -s", "safe", impact="safe")
        check("macOS uname grouped flags", "uname -sr -mp", "safe", impact="safe")
        check("formatted date and macOS uname", "date '+%Y-%m-%d %H:%M:%S %Z' && uname -s", "safe", impact="safe")
        check("unmodeled uname option", "uname -S replacement", "medium", impact=None)
        check("unknown command", "distill-unmodeled-example", "medium")
        # These are only data passed to the analyzer, never shell commands to run.
        check("critical shell specimen", "rm -rf /", "critical")

        for interpreter in ["python", "python3", "python3.13"]:
            for script in [
                "print(1)",
                "print('hello', True, None, -2.5, sep=':', end='\\n', flush=True)",
                "print(1); print(2) # import os is just a comment",
                "print('import os; open(\"/etc/passwd\")')",
                "print(1 + 1)",
                "value = (1 + 2) * 3; print(value)",
            ]:
                check(interpreter + " literal", f"{interpreter} -c {shlex.quote(script)}", "low")
            for script in [
                'print(open("/etc/passwd").read())',
                "print(1); import os",
                "print(__import__('os').getcwd())",
                "print(f'{1+1}')",
                "print(1, file=open('output.txt', 'w'))",
            ]:
                check(interpreter + " extra code", f"{interpreter} -c {shlex.quote(script)}", "high")
        check("python first -c wins", "python3 -c 'print(1); import os' -c 'print(2)'", "high")
        check("python arguments are inert", "python3 -c 'print(1)' -c 'import os'", "low")
        check("python script before -c", "python3 uninspected.py -c 'print(1)'", "high")
        check("python module before -c", "python3 -m uninspected -c 'print(1)'", "high")
        check("python startup option", "python3 -i -c 'print(1)'", "high")
        check("python ordinary flags", "python3 -u -B -c 'print(1)'", "low")
        check("python dynamic script", 'python3 -c "$SCRIPT"', "high")
        py = fixture("hello.py", 'value = 1 + 2\nprint(value)\n')
        check("python source file", f"python3 {py}", "low")
        check("python file arguments are inert", f"python3 {py} -c 'import os'", "low")
        check("python file read effect", "python3 -c 'print(open(\"/etc/passwd\").read())'", "high", "source.file-read")
        check("python file write effect", "python3 -c 'open(\"output.txt\", \"w\")'", "high", "source.file-write")
        check("python root deletion effect", "python3 -c 'import shutil; shutil.rmtree(\"/\")'", "critical", "source.file-delete")
        check("python strongest source finding", "python3 -c 'import os, shutil; os.remove(\"a\"); shutil.rmtree(\"/\")'", "critical", "source.file-delete")
        check("python shadowed print", "python3 -c 'print = 1; print(1)'", "high")
        check("python annotated expression", "python3 -c 'value: unknown() = 1; print(value)'", "high")
        check("python syntax error", "python3 -c 'print(1'", "high")
        check("unicode source and report", "python3 -c " + shlex.quote("print('" + "a" * 495 + "🟢" * 30 + "')"), "low")
        check("literal tilde is not a home path", "python3 -c 'import shutil; shutil.rmtree(\"~\")'", "high", "source.file-delete")

        js = fixture("hello.js", 'console.log("hello");\n')
        js_extra = fixture("extra.js", 'console.log("hello"); require("fs").readFileSync("data.txt");\n')
        for option in ["-e", "--eval"]:
            check("node inline " + option, f"node {option} 'console.log(1, true, null, \"hi\")'", "low")
        for script in [
            "console.log(process.env)",
            "console.log(1); require('fs')",
            "console.log(`${process.cwd()}`)",
            "console.log((() => 1)())",
        ]:
            check("node extra code", "node -e " + shlex.quote(script), "high")
        check("node source file", f"node {js}", "low")
        check("node extra source", f"node {js_extra}", "high")
        check("node preload", "node --require ./uninspected.js -e 'console.log(1)'", "high")
        check("node missing file", "node missing.js", "high")
        check("node dynamic script", 'node -e "$SCRIPT"', "high")
        check("node oversized source", "node " + fixture("large.js", 'console.log("hi");' + " " * 65536), "high")
        check("node primitive binding", "node -e 'const value = (1 + 2) * 3; console.log(value)'", "low")
        check("node block comment", "node -e '/* comment */ console /* comment */ . log(1)'", "low")
        check("node shadowed console", "node -e 'const console = {}; console.log(1)'", "high")
        check("node syntax error", "node -e 'console.log(1) +'", "high")
        check("node source read effect", f"node {js_extra}", "high", "source.file-read")
        check("node recursive root deletion", "node -e 'require(\"fs\").rmSync(\"/\", {recursive: true})'", "critical", "source.file-delete")
        check("node nonrecursive deletion", "node -e 'require(\"fs\").rmSync(\"/\")'", "high", "source.file-delete")
        check("node duplicate recursive option", "node -e 'require(\"fs\").rmSync(\"/\", {recursive: true, recursive: false})'", "high", "source.file-delete")
        check("node quoted recursive option", "node -e 'require(\"fs\").rmSync(\"/\", {\"recursive\": true})'", "critical", "source.file-delete")
        check("node preload after eval", "node -e 'console.log(1)' --require ./uninspected.js", "high")
        check("node repeated eval", "node -e 'console.log(1)' -e 'console.log(2)'", "high")
        fixture("fake-home/same.js", 'console.log("hello");\n')
        fixture("~/same.js", 'require("fs").readFileSync("data.txt");\n')
        check("unquoted source tilde expands", "node ~/same.js", "low")
        check("quoted source tilde is literal", "node '~/same.js'", "high", "source.file-read")
        fixture("ab.js", 'console.log("hello");\n')
        fixture("a\\b.js", 'require("fs").readFileSync("data.txt");\n')
        check("quoted source backslash is literal", 'node "a\\b.js"', "high", "source.file-read")
        fixture("fake-home/code/hello.js", 'console.log("hello");\n')
        fixture("~/code/hello.js", 'require("fs").readFileSync("data.txt");\n')
        check("quoted cd tilde is literal", "cd '~/code'; node hello.js", "high", "source.file-read")
        check("shell line continuation", "no\\\nde -e 'console.log(1)'", "low")
        check("untrusted Node executable", "/tmp/untrusted/node -e 'console.log(1)'", "high")
        check("untrusted Python executable", "/tmp/untrusted/python3 -c 'print(1)'", "high")

        go_source = 'package main\nimport "fmt"\nfunc main() {\n    fmt.Println("hello")\n}\n'
        go = fixture("hello.go", go_source)
        check("go source", f"go run {go}", "low")
        check("go readonly module flag", f"go run -mod=readonly {go}", "low")
        check("go package", "go run .", "high")
        check("go unsupported flags", f"go run -exec ./uninspected {go}", "high")
        check("go missing file", "go run missing.go", "high")
        check("go extra import", "go run " + fixture("extra.go", go_source.replace('import "fmt"', 'import "fmt"\nimport "os"')), "high")
        check("go comment cannot hide code", "go run " + fixture("hidden.go", go_source.replace('import "fmt"', 'import "fmt"\nimport "os" /* comment */')), "high")

        cpp_source = '#include <iostream>\nint main() {\n    std::cout << "hello\\n";\n    return 0;\n}\n'
        cpp = fixture("hello.cpp", cpp_source)
        output = shlex.quote(str(root / "program"))
        for compiler in ["clang", "clang++", "gcc", "g++", "cc", "c++"]:
            check(compiler + " C++ compile/run", f"{compiler} -std=c++17 -O0 {cpp} -o {output} && {output}", "low")
        for extension in ["cc", "cxx"]:
            source = fixture("hello." + extension, cpp_source)
            check("C++ extension " + extension, f"clang++ {source} -o {output} && {output}", "low")
        c = fixture("hello.c", '#include <stdio.h>\nint main(void) {\n    puts("hello");\n    return 0;\n}\n')
        check("C literal puts", f"cc {c} -o {output} && {output}", "low")
        c_printf = fixture("printf.c", '#include <stdio.h>\nint main(void){ printf("hello\\n"); return 0; }\n')
        check("C literal printf", f"cc {c_printf} -o {output} && {output}", "low")
        c_trigraph = fixture("trigraph.c", '#include <stdio.h>\nint main(void){ printf("??/x25n"); return 0; }\n')
        check("C preprocessing escape", f"cc -std=c99 {c_trigraph} -o {output}", "high")
        check("C++ unmodeled code", "clang++ " + fixture("extra.cpp", cpp_source.replace('    return 0;', '    std::cin.get();\n    return 0;')), "high")
        check("C++ comment cannot hide code", "clang++ " + fixture("hidden.cpp", cpp_source.replace('    return 0;', '    std::cin.get(); /* comment */\n    return 0;')), "high")
        check("C++ compiler plugin", f"clang++ -fplugin=uninspected.so {cpp}", "high")
        check("C++ missing source", "clang++ missing.cpp", "high")
        for operator in [";", "||", "|"]:
            check("C++ failed compile " + operator, f"clang++ {cpp} -o {output} {operator} {output}", "medium")
        check("C++ intervening command", f"clang++ {cpp} -o {output} && echo changed && {output}", "medium")
        check("C++ default output", f"clang++ {cpp} && ./a.out", "low")
        existing = fixture("existing-output", "valuable contents\n")
        check("C++ output overwrite", f"clang++ {cpp} -o {existing}", "medium", "write.file")
        check("C++ source overwrite", f"clang++ {cpp} -o source.py", "medium", "write.file")
        check("C++ startup file output", f"clang++ {cpp} -o .zshrc", "high", "write.startup")
        check("C++ root output", f"clang++ {cpp} -o /", "critical", "write.protected")
        link = root / "output-link"
        link.symlink_to(root / "existing-output")
        check("C++ symlink output", f"clang++ {cpp} -o {shlex.quote(str(link))}", "medium", "write.file")

        rust_source = 'fn main() {\n    println!("hello");\n}\n'
        rust = fixture("hello.rs", rust_source)
        for edition in ["--edition=2021", "--edition 2024"]:
            check("rust " + edition, f"rustc {edition} {rust} -o {output} && {output}", "low")
        check("rust extra code", "rustc " + fixture("extra.rs", rust_source.replace('    println!', '    std::env::current_dir().unwrap();\n    println!')), "high")
        check("rust comment cannot hide code", "rustc " + fixture("hidden.rs", rust_source.replace('    println!', '    std::env::current_dir().unwrap(); /* comment */\n    println!')), "high")
        check("rust formatted expression", "rustc " + fixture("format.rs", 'fn main() {\n    println!("{value}");\n}\n'), "high")
        check("rust unmodeled flags", f"rustc --extern uninspected=lib.rlib {rust}", "high")
        check("rust missing source", "rustc missing.rs", "high")
        check("rust failed compile", f"rustc {rust} -o {output} || {output}", "medium")
        check("rust default output", f"rustc {rust} && ./hello", "low")

        for compiler, extension, source in [
            ("go run", "go", 'package main\nimport "fmt"\nfunc main(){ /* comment */ fmt.Println("http://example.com") }\n'),
            ("cc", "c", '#include <stdio.h>\nint main(void){ /* comment */ puts("http://example.com"); return 0; }\n'),
            ("clang++", "cpp", '#include <iostream>\nint main(){ /* comment */ std::cout << "http://example.com"; return 0; }\n'),
            ("rustc", "rs", 'fn main(){ /* comment */ println!("http://example.com"); }\n'),
        ]:
            check("native layout " + extension, f"{compiler} " + fixture("layout." + extension, source), "low")

        for command in ["python3 --version", "node --version", "go version", "rustc --version", "clang++ --version", "cc --version"]:
            check("language version", command, "safe")
        for command in [
            "NODE_OPTIONS=--require=./uninspected.js node -e 'console.log(1)'",
            "env PYTHONPATH=./uninspected python3 -c 'print(1)'",
            "PATH=./uninspected node -e 'console.log(1)'",
            f"GOFLAGS=-exec=./uninspected go run {go}",
            f"RUSTC_WRAPPER=./uninspected rustc {rust}",
        ]:
            check("runtime environment override", command, "high", "exec.runtime-environment")

        # Other languages in the command catalog have generic execution profiles,
        # without a specialized literal-print exception.
        for command in [
            "perl -e 'print 1'",
            "ruby -e 'puts 1'",
            "php -r 'echo 1;'",
            "lua -e 'print(1)'",
            "swift -e 'print(1)'",
            "swiftc hello.swift",
            "java Hello",
            "javac Hello.java",
            "jsc hello.js",
            "osascript -e 'return 1'",
        ]:
            check("generic language fallback", command, "high")

    if failures:
        raise SystemExit(f"{len(failures)} failures in {checks} language cases:\n" + "\n".join(failures))
    print(f"language smoke ok: {checks} analyses and {checks} approval-label checks (max analysis {max(timings)} ms)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: language_smoke.py <distill-binary>")
    main(sys.argv[1])
