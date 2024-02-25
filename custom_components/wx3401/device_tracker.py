"""Platform for device_tracker integration."""
import logging
from typing import Any, Callable

from homeassistant.components.device_tracker import SOURCE_TYPE_ROUTER
from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import (
    COORDINATOR,
    COORDINATOR_LISTENER,
    DOMAIN,
    ENTITIES,
    WX3401DataUpdateCoordinator,
)

logger = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: Callable[..., None],
) -> None:
    """Add sensors for passed config_entry in HA."""

    coordinator: WX3401DataUpdateCoordinator = hass.data[DOMAIN][config_entry.entry_id][
        COORDINATOR
    ]

    @callback  # type: ignore
    def async_discover_sensor() -> None:
        wlan_devices: dict[str, dict[str, str]] = coordinator.data
        logger.debug(f"WX3401 DEVICES {wlan_devices}")
        entities = hass.data[DOMAIN][config_entry.entry_id][ENTITIES]

        async_add_entities(
            WX3401DeviceTracker(coordinator, mac_addr, device_info, config_entry)
            for mac_addr, device_info in wlan_devices.items()
            if mac_addr not in entities
        )

    hass.data[DOMAIN][config_entry.entry_id][
        COORDINATOR_LISTENER
    ] = async_discover_sensor

    async_discover_sensor()

    coordinator.async_add_listener(async_discover_sensor)


class WX3401DeviceTracker(CoordinatorEntity, ScannerEntity):  # type: ignore
    """Representing a device connected to wx3401."""

    #'Address', 'Rate(kbps)', 'RSSI', 'SNR', 'Level'
    def __init__(
        self,
        coordinator: WX3401DataUpdateCoordinator,
        mac_address: str,
        initial_data: dict[str, str],
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize wx3401 sensor."""
        super().__init__(coordinator)
        self._data = initial_data
        self._mac = mac_address
        self._config_entry = config_entry
        self._connected = True
        self._name = mac_address

    @property
    def available(self) -> Any:
        """Return if sensor is available."""
        # Sensor is available as long we have connectivity to the router
        return self.coordinator.last_update_success

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if the entity should be enabled when first added to the entity registry."""
        return True

    @property
    def source_type(self) -> Any:
        """Return the source type."""
        return SOURCE_TYPE_ROUTER

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def mac_address(self) -> str | None:
        return self._mac

    @property
    def extra_state_attributes(self) -> dict[str, str | None]:
        return {
            "rssi": self.rssi,
            "snr": self.snr,
            "level": self.level,
            "rate": self.rate,
        }

    @property
    def rssi(self) -> str | None:
        return self._data.get("RSSI")

    @property
    def snr(self) -> str | None:
        return self._data.get("SNR")

    @property
    def level(self) -> str | None:
        return self._data.get("Level")

    @property
    def rate(self) -> str | None:
        return self._data.get("Rate(kbps)")

    @property
    def icon(self) -> str:
        """Return the icon."""
        return "mdi:devices"

    def update(self) -> None:
        logger.debug(f"entity={self._mac} update() was called")
        self._handle_coordinator_update()

    async def async_added_to_hass(self) -> None:
        """Run when this Entity has been added to HA."""
        entities = self.hass.data[DOMAIN][self._config_entry.entry_id][ENTITIES]
        entities[self._mac] = self._mac
        self.coordinator.async_add_listener(self._handle_coordinator_update)
        await super().async_added_to_hass()

    async def async_will_remove_from_hass(self) -> None:
        """Entity being removed from hass."""
        entities = self.hass.data[DOMAIN][self._config_entry.entry_id][ENTITIES]
        entities.pop(self._mac)
        self.coordinator.async_remove_listener(self._handle_coordinator_update)
        await super().async_will_remove_from_hass()

    @callback  # type: ignore
    def _handle_coordinator_update(self) -> None:
        wifi_devices: dict[str, dict[str, str]] = self.coordinator.data
        self._connected = False

        if wifi_devices and self._mac in wifi_devices:
            self._data = wifi_devices[self._mac]
            self._connected = True

        logger.debug(f"entity={self._mac} was updated via _handle_coordinator_update")
        self.async_write_ha_state()
        # May need to handle this differently in future versions of hass
        # super()._handle_coordinator_update()
