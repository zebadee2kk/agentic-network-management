from typing import Any

from nats.js.errors import NotFoundError


async def ensure_stream(js: Any, *, name: str, subjects: list[str]) -> None:
    """Create a JetStream stream or add newly required subjects without dropping existing ones."""
    desired = set(subjects)
    try:
        info = await js.stream_info(name)
    except NotFoundError:
        await js.add_stream(name=name, subjects=sorted(desired), storage="file")
        return

    current = set(info.config.subjects or [])
    merged = current | desired
    if merged != current:
        await js.update_stream(
            config=info.config,
            subjects=sorted(merged),
        )
