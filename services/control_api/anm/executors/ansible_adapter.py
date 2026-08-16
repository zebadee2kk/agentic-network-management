import asyncio
import json
import os
import tempfile
from importlib import resources
from pathlib import Path
from typing import Any

from anm.executors.base import ExecutionContext, ExecutionOutcome


class AnsibleExecutor:
    def __init__(self, *, platform: str) -> None:
        if platform not in {"windows", "linux"}:
            raise ValueError("unsupported ansible platform")
        self._platform = platform

    @staticmethod
    def _artifact_path(relative_path: str) -> Path:
        if not relative_path.startswith("execution_artifacts/"):
            raise ValueError("ansible implementation must be a reviewed execution artifact")
        resource = resources.files("anm").joinpath(relative_path)
        path = Path(str(resource)).resolve()
        if not path.is_file():
            raise ValueError("reviewed ansible implementation is missing")
        return path

    def _inventory(
        self,
        context: ExecutionContext,
        secret: dict[str, Any],
        private_key_path: str | None,
    ) -> dict[str, Any]:
        username = secret.get("username")
        if not isinstance(username, str) or not username:
            raise ValueError("execution credential is missing username")
        host_vars: dict[str, Any] = {
            "ansible_host": context.endpoint,
            "ansible_user": username,
        }
        password = secret.get("password")
        if isinstance(password, str) and password:
            host_vars["ansible_password"] = password

        if self._platform == "windows":
            host_vars.update(
                {
                    "ansible_connection": "winrm",
                    "ansible_port": int(context.binding_config.get("port", 5986)),
                    "ansible_winrm_transport": str(
                        context.binding_config.get("winrm_transport", "ntlm")
                    ),
                    "ansible_winrm_server_cert_validation": str(
                        context.binding_config.get("server_cert_validation", "validate")
                    ),
                }
            )
        else:
            host_vars.update(
                {
                    "ansible_connection": "ssh",
                    "ansible_port": int(context.binding_config.get("port", 22)),
                }
            )
            if private_key_path is not None:
                host_vars["ansible_ssh_private_key_file"] = private_key_path
        return {"all": {"hosts": {"target": host_vars}}}

    async def execute(self, context: ExecutionContext) -> ExecutionOutcome:
        if context.secret is None:
            return ExecutionOutcome(outcome="failed", category="credential_unavailable")
        playbook = self._artifact_path(context.implementation)
        service_name = context.parameters.get("service_name")
        if not isinstance(service_name, str) or not service_name:
            return ExecutionOutcome(outcome="failed", category="invalid_service_parameter")

        runtime_root = Path("/run/anm-executor")
        runtime_root.mkdir(parents=True, exist_ok=True)
        timeout = float(context.binding_config.get("timeout_seconds", 120))
        try:
            with tempfile.TemporaryDirectory(dir=runtime_root) as directory:
                temp_dir = Path(directory)
                private_key_path: str | None = None
                private_key = context.secret.get("private_key")
                if isinstance(private_key, str) and private_key:
                    key_file = temp_dir / "id_key"
                    key_file.write_text(private_key, encoding="utf-8")
                    os.chmod(key_file, 0o600)
                    private_key_path = str(key_file)

                inventory_file = temp_dir / "inventory.json"
                inventory = self._inventory(context, context.secret, private_key_path)
                inventory_file.write_text(json.dumps(inventory), encoding="utf-8")
                os.chmod(inventory_file, 0o600)

                variables_file = temp_dir / "vars.json"
                variables_file.write_text(
                    json.dumps({"anm_service_name": service_name}),
                    encoding="utf-8",
                )
                os.chmod(variables_file, 0o600)

                process = await asyncio.create_subprocess_exec(
                    "ansible-playbook",
                    "-i",
                    str(inventory_file),
                    str(playbook),
                    "--extra-vars",
                    f"@{variables_file}",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    env={
                        **os.environ,
                        "ANSIBLE_NOCOLOR": "1",
                        "ANSIBLE_LOCAL_TEMP": str(temp_dir / "local"),
                    },
                )
                try:
                    return_code = await asyncio.wait_for(process.wait(), timeout=timeout)
                except TimeoutError:
                    process.kill()
                    await process.wait()
                    return ExecutionOutcome(
                        outcome="ambiguous",
                        category="remote_execution_timeout",
                    )
        except (OSError, ValueError, TypeError):
            return ExecutionOutcome(outcome="failed", category="executor_configuration_error")

        if return_code != 0:
            return ExecutionOutcome(outcome="failed", category="ansible_nonzero_exit")
        return ExecutionOutcome(
            outcome="success",
            result={"adapter": f"ansible_{self._platform}", "return_code": 0},
        )
