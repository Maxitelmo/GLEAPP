"""A stand-in for c2pa-python, with the surface gleapp.provenance uses.

The surface is c2pa-python 0.38.0's: ``Settings.from_dict``, ``Context(settings=)``,
``Reader(mime, stream, context=)`` with ``json()`` and ``close()``, ``C2paError`` with
its ``ManifestNotFound`` and ``RemoteManifest`` subclasses, and ``sdk_version()``.
"""

import json
import sys
import types


class FakeC2pa(types.ModuleType):
    """The surface of c2pa-python 0.38.0 that read_provenance uses."""

    def __init__(self, *, store=None, raises=None):
        super().__init__("c2pa")
        self.calls = []
        self.settings = []
        fake = self

        class C2paError(Exception):
            pass

        class ManifestNotFound(C2paError):
            pass

        class RemoteManifest(C2paError):
            pass

        C2paError.ManifestNotFound = ManifestNotFound
        C2paError.RemoteManifest = RemoteManifest
        self.C2paError = C2paError

        class Settings:
            @staticmethod
            def from_dict(d):
                fake.settings.append(d)
                return d

        class Context:
            def __init__(self, settings=None):
                self.settings = settings

        class Reader:
            def __init__(self, mime, stream, context=None):
                fake.calls.append((mime, context.settings if context else None))
                stream.read()
                if raises is not None:
                    raise raises(fake)

            def json(self):
                return json.dumps(store)

            def close(self):
                pass

        self.Settings, self.Context, self.Reader = Settings, Context, Reader

    @staticmethod
    def sdk_version():
        return "0.0.0-standin"


def install_fake_c2pa(monkeypatch, **kw) -> FakeC2pa:
    """Put a FakeC2pa where ``import c2pa`` finds it, for the length of one test."""
    mod = FakeC2pa(**kw)
    monkeypatch.setitem(sys.modules, "c2pa", mod)
    return mod
