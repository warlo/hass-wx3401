import logging
from datetime import timedelta
from typing import Any

import aiohttp
from aiohttp.client_exceptions import ClientConnectorError
from async_timeout import timeout
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import Unauthenticated, WX3401Client, WX3401ClientError

DOMAIN = "wx3401"
COORDINATOR = "coordinator"
ENTITIES = "entities"
COORDINATOR_LISTENER = "coordinator-listener"

PLATFORMS = ["device_tracker"]

logger = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    hass.data.setdefault(DOMAIN, {})

    # Return boolean to indicate that initialization was successful.
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up WX3401 from a config entry."""

    # Create jar for storing session cookies
    jar = aiohttp.CookieJar(unsafe=True)

    # WX3401 uses session cookie so we need a we client with a cookie jar
    client_sesssion = async_create_clientsession(hass, False, True, cookie_jar=jar)

    coordinator = WX3401DataUpdateCoordinator(
        hass,
        client_sesssion,
        entry.data[CONF_HOST],
        entry.data[CONF_USERNAME],
        entry.data[CONF_PASSWORD],
    )
    await coordinator.async_refresh()

    if not coordinator.last_update_success:
        raise ConfigEntryNotReady

    hass.data[DOMAIN][entry.entry_id] = {
        COORDINATOR: coordinator,
        ENTITIES: {},
        COORDINATOR_LISTENER: None,
    }

    # Setup the platforms for the wx3401 integration
    for component in PLATFORMS:
        hass.async_create_task(
            hass.config_entries.async_forward_entry_setup(entry, component)
        )

    return True


class WX3401DataUpdateCoordinator(DataUpdateCoordinator):  # type: ignore
    """Class to manage fetching WX3401 data from router."""

    def __init__(
        self,
        hass: HomeAssistant,
        session: aiohttp.ClientSession,
        hostname: str,
        username: str,
        password: str,
    ) -> None:
        """Initialize."""
        self._session = session
        self._hostname = hostname
        self._username = username
        self._password = password

        self._client = WX3401Client(
            self._session, self._hostname, self._username, self._password
        )

        # TODO: Make this a configurable value
        update_interval = timedelta(seconds=10)
        logger.debug("Data will be update every %s", update_interval)

        super().__init__(hass, logger, name=DOMAIN, update_interval=update_interval)

    async def _async_update_data(self) -> dict[str, dict[str, str]]:
        """Update data via library."""
        try:
            async with timeout(10):
                devices = await self._client.get_wlan_dict()
        except Unauthenticated:
            await self._client.login()
            devices = await self._client.get_wlan_dict()
        except (WX3401ClientError, ClientConnectorError) as error:
            raise UpdateFailed(error) from error
        return devices
