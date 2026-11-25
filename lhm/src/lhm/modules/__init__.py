"""Apply modules, with the default modules in DESIGN.md execution order.

``services`` (``apply cleanup-services``) is interactive, so ``apply all``
deliberately skips it. Caddy is resolved only for an explicit ``apply caddy``.
"""

from dataclasses import dataclass

from lhm.core.report import StepResult
from lhm.core.runner import Runner
from lhm.modules.alert import AlertModule
from lhm.modules.audit import AuditModule
from lhm.modules.backup import BackupModule
from lhm.modules.fail2ban import Fail2banModule
from lhm.modules.firewall import FirewallModule
from lhm.modules.logging import LoggingModule
from lhm.modules.sandbox import SandboxModule
from lhm.modules.services import ServicesModule
from lhm.modules.ssh import SshModule
from lhm.modules.sysctl import SysctlModule
from lhm.modules.updates import UpdatesModule


class Module:
    name: str = ""
    description: str = ""
    implemented: bool = False

    def apply(self, runner: Runner, **options: object) -> list[StepResult]:
        raise NotImplementedError(self.name)


@dataclass(frozen=True)
class PlannedModule(Module):
    name: str
    description: str


MODULES: tuple[Module, ...] = (
    UpdatesModule(),
    SshModule(),
    FirewallModule(),
    Fail2banModule(),
    ServicesModule(),
    SysctlModule(),
    SandboxModule(),
    LoggingModule(),
    AuditModule(),
    AlertModule(),
    BackupModule(),
)

# ``apply all`` order: module table order minus the interactive cleanup-services.
APPLY_ALL_ORDER: tuple[str, ...] = tuple(
    module.name for module in MODULES if module.name != "services"
)


def resolve(name: str) -> Module | None:
    if name == "caddy":
        from lhm.modules.caddy import CaddyModule

        return CaddyModule()
    for module in MODULES:
        if module.name == name:
            return module
    return None
