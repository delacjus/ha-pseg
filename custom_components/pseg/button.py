"""Buttons for the PSE&G Energy integration."""

from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
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
            name=f"PSE&G ({entry.title or 'Energy'})",
            manufacturer="Public Service Enterprise Group",
            model="Smart AMI Meter",
        )

    async def async_press(self) -> None:
        """Handle manual refresh press."""
        _LOGGER.info("Manual refresh triggered via PSE&G Refresh button")
        await self.coordinator.async_request_refresh()
