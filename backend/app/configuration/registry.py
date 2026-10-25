from __future__ import annotations

from app.configuration.cisco_ios import CISCO_IOS_ADAPTER
from app.configuration.contracts import ConfigurationAdapterRegistry
from app.configuration.ssh_cli import GENERIC_SSH_ADAPTER
from app.configuration.telnet_cli import GENERIC_TELNET_ADAPTER


registry = ConfigurationAdapterRegistry()
registry.register(GENERIC_SSH_ADAPTER)
registry.register(GENERIC_TELNET_ADAPTER)
registry.register(CISCO_IOS_ADAPTER)
