#!/usr/bin/env python3
"""Run Auth admission races against an explicitly owned, disposable database."""
import argparse
import collections
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", choices=("Debug", "Release"), default="Debug")
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("This Docker Linux-container harness requires a POSIX runner.")
    root = Path(__file__).resolve().parent.parent
    owner = str(uuid.uuid4())
    database = "gma_auth_admission_" + uuid.uuid4().hex
    password = uuid.uuid4().hex
    output = root / "artifacts" / "auth-admission" / owner
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    proof = {"owner": owner, "database": database, "configuration": args.configuration,
             "productionStateUsed": False, "containerRemoved": False}
    container = None
    container_file = output / "container.id"

    def command(arguments, *, environment=None, timeout=120, input_text=None):
        process = subprocess.Popen(arguments, cwd=root, env=environment,
                                   stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, start_new_session=True)
        try:
            captured, _ = process.communicate(input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=10)
            raise RuntimeError("Owned Auth admission command exceeded its time budget") from None
        return process.returncode, captured.replace(password, "[redacted]")

    def checked(arguments, **kwargs):
        code, captured = command(arguments, **kwargs)
        if code:
            raise RuntimeError(f"Owned Auth admission command failed ({code}): {captured[-6000:]}")
        return captured.strip()

    try:
        endpoint = os.environ.get("DOCKER_HOST", "")
        if endpoint and not endpoint.startswith("unix:"):
            raise RuntimeError("Only a local Unix Docker endpoint is supported")
        context_endpoint = json.loads(checked([
            "docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"]))
        if not context_endpoint.startswith("unix:"):
            raise RuntimeError("Only a local Unix Docker context is supported")
        env = dict(os.environ, POSTGRES_PASSWORD=password, POSTGRES_DB=database)
        checked([
            "docker", "run", "-d", "--name", "gma-auth-admission-" + owner,
            "--cidfile", str(container_file),
            "--label", "io.gma.auth-admission.owner=" + owner,
            "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
            "--mount", "type=tmpfs,destination=/var/lib/postgresql/data,tmpfs-size=536870912",
            "-p", "127.0.0.1::5432", "-e", "POSTGRES_PASSWORD", "-e", "POSTGRES_DB",
            "postgres:16-alpine"], environment=env)
        container = container_file.read_text().strip()
        if re.fullmatch(r"[0-9a-f]{64}", container) is None:
            raise RuntimeError("Docker did not retain an exact container identity")
        record = json.loads(checked(["docker", "inspect", container]))[0]
        ports = record["NetworkSettings"]["Ports"]["5432/tcp"]
        if len(ports) != 1 or ports[0]["HostIp"] != "127.0.0.1":
            raise RuntimeError("Owned PostgreSQL must expose exactly one loopback binding")
        proof.update(containerId=container, imageId=record["Image"], loopbackOnly=True)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            code, _ = command(["docker", "exec", container, "pg_isready", "-h", "127.0.0.1",
                               "-U", "postgres", "-d", database], timeout=10)
            if not code:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("Owned PostgreSQL did not become ready")
        checked(["docker", "exec", "-i", container, "psql", "-v", "ON_ERROR_STOP=1",
                 "-U", "postgres", "-d", database],
                input_text=f'COMMENT ON DATABASE "{database}" IS \'gma-auth-admission-owner:{owner}\';')
        test_env = dict(os.environ, GMA_AUTH_ADMISSION_PG_OWNER=owner,
                        GMA_AUTH_ADMISSION_PG_CONNECTION=(
                            f"Host=127.0.0.1;Port={ports[0]['HostPort']};Database={database};"
                            f"Username=postgres;Password={password}"))
        arguments = ["dotnet", "test", "tests/Gma.Modules.Auth.Tests/Gma.Modules.Auth.Tests.csproj",
                     "--configuration", args.configuration,
                     "--filter", "FullyQualifiedName~AuthTransactionAdmissionPostgreSqlTests",
                     "--logger", "trx;LogFileName=admission.trx", "--results-directory", str(output),
                     "-m:1", "/p:UseSharedCompilation=false"]
        if args.no_build:
            arguments.extend(["--no-build", "--no-restore"])
        code, log = command(arguments, environment=test_env, timeout=900)
        (output / "tests.log").write_text(log)
        proof["testExitCode"] = code
        trx = output / "admission.trx"
        results = [] if not trx.exists() else ET.parse(trx).findall(
            ".//{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}UnitTestResult")
        outcomes = dict(collections.Counter(row.attrib["outcome"] for row in results))
        proof["outcomes"] = outcomes
        if code or not results or outcomes != {"Passed": len(results)}:
            raise RuntimeError("Auth admission tests failed, skipped, or did not execute; inspect minimized evidence")
    finally:
        try:
            if container is None and container_file.exists():
                candidate = container_file.read_text().strip()
                if re.fullmatch(r"[0-9a-f]{64}", candidate):
                    container = candidate
            if container:
                record = json.loads(checked(["docker", "inspect", container]))[0]
                if record["Config"]["Labels"].get("io.gma.auth-admission.owner") != owner:
                    raise RuntimeError("Refusing to remove a container without the exact owner label")
                checked(["docker", "rm", "-f", "-v", container])
                proof["containerRemoved"] = True
        finally:
            (output / "proof.json").write_text(json.dumps(proof, indent=2) + "\n")
            for path in output.iterdir():
                if path.is_file():
                    # Provider failures may include a connection string in TRX output.
                    path.write_text(path.read_text().replace(password, "[redacted]"))
                    path.chmod(0o600)
    print(json.dumps(proof))


if __name__ == "__main__":
    main()
