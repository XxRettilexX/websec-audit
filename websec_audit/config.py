"""Target configuration loading and validation."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import yaml


class ConfigError(Exception):
    pass


@dataclass
class Target:
    url: str
    authorized: bool = False
    mode: str = "passive"  # "passive" or "active"
    extra_params: List[str] = field(default_factory=list)

    def validate(self) -> None:
        if self.mode not in ("passive", "active"):
            raise ConfigError(f"Modalità non valida per {self.url!r}: {self.mode!r}")
        if self.mode == "active" and not self.authorized:
            raise ConfigError(
                f"Target {self.url!r} è in modalità 'active' ma non è marcato "
                f"'authorized: true'. Testare un sito non tuo (o senza autorizzazione "
                f"scritta) in modalità attiva non è consentito da questo strumento."
            )


def load_targets_from_file(path: str) -> List[Target]:
    data = yaml.safe_load(Path(path).read_text())
    if not data or "targets" not in data:
        raise ConfigError("Il file di configurazione deve contenere una chiave 'targets'.")
    targets = []
    for entry in data["targets"]:
        t = Target(
            url=entry["url"],
            authorized=bool(entry.get("authorized", False)),
            mode=entry.get("mode", "passive"),
            extra_params=entry.get("extra_params", []),
        )
        t.validate()
        targets.append(t)
    return targets


def build_single_target(url: str, active: bool, i_own_this_target: bool) -> Target:
    mode = "active" if active else "passive"
    t = Target(url=url, authorized=i_own_this_target, mode=mode)
    t.validate()
    return t
