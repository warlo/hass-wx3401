"""Config flow for Amplify integration."""
import logging
from typing import Any

import aiohttp
import voluptuous as vol
from homeassistant import config_entries, core, exceptions
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from . import DOMAIN
from .client import WX3401Client

_LOGGER = logging.getLogger(__name__)

DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST, default="https://192.168.1.2"): str,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


async def validate_input(
    hass: core.HomeAssistant, data: dict[str, str]
) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys from DATA_SCHEMA with values provided by the user.
    """

    jar = aiohttp.CookieJar(unsafe=True)
    session = async_create_clientsession(hass, False, True, cookie_jar=jar)
    client = WX3401Client(
        session, data[CONF_HOST], data[CONF_USERNAME], data[CONF_PASSWORD]
    )

    result = await client.get_wlan_dict()
    if not result:
        raise CannotConnect()

    return {"title": data[CONF_HOST]}


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):  # type: ignore
    """Handle a config flow for WX3401."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_LOCAL_POLL

    async def async_step_user(self, user_input: dict[str, str] | None = None) -> Any:
        """Handle the initial step."""

        errors = {}
        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)

                return self.async_create_entry(title=info["title"], data=user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidHost:
                errors["host"] = "cannot_connect"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        # If there is no user input or there were errors, show the form again,
        # including any errors that were found with the input.
        return self.async_show_form(
            step_id="user", data_schema=DATA_SCHEMA, errors=errors
        )


class CannotConnect(exceptions.HomeAssistantError):  # type: ignore
    """Error to indicate we cannot connect."""


class InvalidHost(exceptions.HomeAssistantError):  # type: ignore
    """Error to indicate there is an invalid hostname."""
