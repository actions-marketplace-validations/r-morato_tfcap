#!/usr/bin/env python3
"""Benchmark tfcap against public Terraform module repositories.

Usage: bench/run.py <tfcap-binary> <repos-dir> <out.json>

<repos-dir> holds one git checkout per repository (see bench/repos.txt).
Every directory with .tf files in a repository, except examples/ and
tests, is scanned as a third-party module, the way it would be if you
called it from your own configuration. Stdlib only.
"""
import json, os, subprocess, sys, tempfile, time

SKIP = {"examples", "example", "test", "tests", "fixtures", ".terraform", ".git", "wrappers", "docs"}


def module_dirs(repo):
    for root, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in SKIP and not d.startswith("."))
        if any(f.endswith((".tf", ".tf.json", ".tofu")) for f in files):
            yield root


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True).stdout.strip()


def main():
    tfcap, repos_dir, out = sys.argv[1:4]
    results = []
    for name in sorted(os.listdir(repos_dir)):
        repo = os.path.join(repos_dir, name)
        if not os.path.isdir(os.path.join(repo, ".git")):
            continue
        url = git(repo, "remote", "get-url", "origin")
        slug = url.removeprefix("https://github.com/").removesuffix(".git")
        entries = [{"Key": "", "Source": "", "Dir": "."}]
        for i, d in enumerate(module_dirs(repo)):
            rel = os.path.relpath(d, repo)
            src = "github.com/" + slug + ("" if rel == "." else "//" + rel)
            entries.append({"Key": f"m{i}", "Source": src, "Dir": os.path.abspath(d)})
        with tempfile.TemporaryDirectory() as h:
            os.makedirs(os.path.join(h, ".terraform", "modules"))
            with open(os.path.join(h, ".terraform", "modules", "modules.json"), "w") as f:
                json.dump({"Modules": entries}, f)
            t0 = time.perf_counter()
            p = subprocess.run([tfcap, "scan", h, "--format", "json", "--third-party-only", "--fail-on", "none"],
                               capture_output=True, text=True)
            secs = time.perf_counter() - t0
        rep = json.loads(p.stdout)
        keys = {e["Key"]: os.path.relpath(e["Dir"], repo) for e in entries if e["Key"]}
        caps = rep["capabilities"]
        for c in caps:
            c["module_path"] = keys.get(c["module"], c["module"])
        results.append({
            "repo": slug, "commit": git(repo, "rev-parse", "HEAD"),
            "tag": git(repo, "describe", "--tags", "--always"),
            "modules": len(entries) - 1,
            "files": sum(m.get("files", 0) for m in rep["modules"] if m["key"]),
            "seconds": round(secs, 3), "capabilities": caps, "errors": rep.get("errors", []),
        })
        print(f"{slug:65} {len(entries)-1:3} modules {len(caps):4} findings {secs:6.2f}s", file=sys.stderr)
    with open(out, "w") as f:
        json.dump(results, f, indent=1)


if __name__ == "__main__":
    main()
