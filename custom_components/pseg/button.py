"""Buttons for the PSE&G Energy integration."""

from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DEVICE_NAME, DOMAIN
from .coordinator import PsegDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up PSE&G button entries."""
    coordinator: PsegDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([PsegRefreshButton(coordinator, entry)])


class PsegRefreshButton(CoordinatorEntity[PsegDataUpdateCoordinator], ButtonEntity):
    """Button to manually trigger an immediate refresh of PSE&G data."""

    _attr_has_entity_name = True
    _attr_translation_key = "refresh_data"
    _attr_icon = "mdi:refresh"

    def __init__(self, coordinator: PsegDataUpdateCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self.entry = entry
        self._attr_unique_id = f"{entry.entry_id}_refresh_data"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            # "PSEG" + has_entity_name gives sensor.pseg_<key>, the ids the card and
            # README use. The meter id goes in serial_number, not the name.
            name=DEVICE_NAME,
            manufacturer="Public Service Enterprise Group",
            model="Smart AMI Meter",
            serial_number=entry.unique_id,
        )

    async def async_press(self) -> None:
        """Handle manual refresh press."""
        _LOGGER.info("Manual refresh triggered via PSE&G Refresh button")
        await self.coordinator.async_request_refresh()
