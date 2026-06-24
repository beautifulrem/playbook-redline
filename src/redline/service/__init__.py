"""HTTP service boundary for Playbook Redline."""

__all__ = ["create_app"]


def __getattr__(name: str):
    if name == "create_app":
        from redline.service.app import create_app

        return create_app
    raise AttributeError(name)
