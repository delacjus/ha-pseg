"""Sensors for the PSE&G Energy integration."""

from __future__ import annotations

from datetime import datetime
import logging
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfEnergy, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .const import (
    ATTR_HISTORY_14D,
    ATTR_LAST_KEEPALIVE,
    ATTR_LAST_SSO_RENEWAL,
    ATTR_LATEST_COST,
    ATTR_LATEST_DATE,
    ATTR_METER,
    ATTR_OKTA_SESSION_EXPIRED_AT,
    ATTR_PREVIOUS_COST,
    ATTR_PREVIOUS_DATE,
    ATTR_PREVIOUS_KWH,
    ATTR_SESSION_ESTABLISHED_AT,
    ATTR_SSO_RENEWALS,
    DOMAIN,
)
from .coordinator import PsegDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up PSE&G sensor entries."""
    coordinator: PsegDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    entities = [
        PsegElectricityConsumptionSensor(coordinator, entry),
        PsegElectricityCostSensor(coordinator, entry),
        PsegElectricityMeterSensor(coordinator, entry),
        PsegElectricityLatestDateSensor(coordinator, entry),
        PsegTemperatureSensor(coordinator, entry),
        PsegNextUpdateSensor(coordinator, entry),
        PsegConnectionStatusSensor(coordinator, entry),
    ]

    async_add_entities(entities)


class PsegBaseSensor(CoordinatorEntity[PsegDataUpdateCoordinator], RestoreEntity, SensorEntity):
    """Base sensor for PSE&G integration with state restoration support."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: PsegDataUpdateCoordinator,
        entry: ConfigEntry,
        key: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.entry = entry
        self._key = key
        self._attr_unique_id = f"{entry.entry_id}_{key}"
        self._attr_translation_key = key
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=f"PSE&G ({entry.title or 'Energy'})",
            manufacturer="Public Service Enterprise Group",
            model="Smart AMI Meter",
        )
        self._restored_state = None

    async def async_added_to_hass(self) -> None:
        """Handle entity added to Home Assistant."""
        await super().async_added_to_hass()
        last_state = await self.async_get_last_state()
        if last_state and last_state.state not in ("unknown", "unavailable"):
            self._restored_state = last_state

    @property
    def available(self) -> bool:
        """Return True if data exists or has previously been loaded."""
        return self._data is not None or self._restored_state is not None

    @property
    def _data(self) -> dict[str, Any] | None:
        """Return coordinator data, falling back to cached last valid data."""
        return self.coordinator.data or getattr(self.coordinator, "_last_valid_data", None)


class PsegConnectionStatusSensor(PsegBaseSensor):
    """Sensor for integration connection and authentication status."""

    def __init__(self, coordinator: PsegDataUpdateCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "connection_status")

    @property
    def available(self) -> bool:
        """Status sensor is always available."""
        return True

    @property
    def native_value(self) -> str:
        """Return connection status: connected, auth_required, or error."""
        return self.coordinator.status

    @property
    def icon(self) -> str:
        if self.coordinator.status == "connected":
            return "mdi:check-circle"
        if self.coordinator.status == "auth_required":
            return "mdi:alert-circle"
        return "mdi:alert-octagon"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return connection and session telemetry attributes."""
        client = self.coordinator.client
        return {
            "auth_required": self.coordinator.auth_required,
            "last_successful_update": self.coordinator.last_successful_update,
            ATTR_SESSION_ESTABLISHED_AT: client.session_established_at,
            ATTR_LAST_SSO_RENEWAL: client.last_sso_renewal,
            ATTR_SSO_RENEWALS: client.sso_renewals,
            ATTR_LAST_KEEPALIVE: client.last_keepalive,
            ATTR_OKTA_SESSION_EXPIRED_AT: client.okta_session_expired_at,
        }


class PsegElectricityConsumptionSensor(PsegBaseSensor):
    """Sensor for electricity consumption in kWh."""

    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR
    _attr_icon = "mdi:lightning-bolt"

    def __init__(self, coordinator: PsegDataUpdateCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "electricity_consumption")

    @property
    def native_value(self) -> float | None:
        """Return the consumption in kWh."""
        if self._data and "latest_kwh" in self._data:
            return self._data.get("latest_kwh")
        if self._restored_state:
            try:
                return float(self._restored_state.state)
            except (ValueError, TypeError):
                pass
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return full history and context attributes for the custom card."""
        attrs = {}
        if self._restored_state and self._restored_state.attributes:
            attrs.update(self._restored_state.attributes)
        if self._data:
            attrs.update({
                ATTR_METER: self._data.get("meter"),
                ATTR_LATEST_DATE: self._data.get("latest_date"),
                ATTR_PREVIOUS_DATE: self._data.get("previous_date"),
                ATTR_PREVIOUS_KWH: self._data.get("previous_kwh"),
                ATTR_PREVIOUS_COST: self._data.get("previous_cost"),
                ATTR_LATEST_COST: self._data.get("latest_cost"),
                ATTR_HISTORY_14D: self._data.get("history_14d", []),
                "last_updated": self._data.get("last_updated"),
                "temperature_range": self._data.get("temperature_range"),
                "next_update": self._data.get("next_update"),
            })
        attrs["auth_required"] = self.coordinator.auth_required
        attrs["connection_status"] = self.coordinator.status
        return attrs


class PsegElectricityCostSensor(PsegBaseSensor):
    """Sensor for electricity cost in USD (estimated)."""

    _attr_device_class = SensorDeviceClass.MONETARY
    _attr_native_unit_of_measurement = "USD"
    _attr_icon = "mdi:currency-usd"

    def __init__(self, coordinator: PsegDataUpdateCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "electricity_cost")

    @property
    def native_value(self) -> float | None:
        """Return the estimated cost in dollars."""
        if self._data and "latest_cost" in self._data:
            return self._data.get("latest_cost")
        if self._restored_state:
            try:
                return float(self._restored_state.state)
            except (ValueError, TypeError):
                pass
        return None


class PsegElectricityMeterSensor(PsegBaseSensor):
    """Sensor for the meter ID/description."""

    _attr_icon = "mdi:meter-electric"

    def __init__(self, coordinator: PsegDataUpdateCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "meter_id")

    @property
    def native_value(self) -> str | None:
        if self._data and "meter" in self._data:
            return self._data.get("meter")
        if self._restored_state:
            return self._restored_state.state
        return None


class PsegElectricityLatestDateSensor(PsegBaseSensor):
    """Sensor for the latest reading date."""

    _attr_icon = "mdi:calendar-clock"

    def __init__(self, coordinator: PsegDataUpdateCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "latest_reading_date")

    @property
    def native_value(self) -> str | None:
        if self._data and "latest_date" in self._data:
            return self._data.get("latest_date")
        if self._restored_state:
            return self._restored_state.state
        return None


class PsegTemperatureSensor(PsegBaseSensor):
    """Sensor for the outdoor average temperature."""

    _attr_device_class = SensorDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement = UnitOfTemperature.FAHRENHEIT
    _attr_icon = "mdi:thermometer"

    def __init__(self, coordinator: PsegDataUpdateCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "outdoor_temperature")

    @property
    def native_value(self) -> float | None:
        if self._data and "temperature_avg" in self._data:
            return self._data.get("temperature_avg")
        if self._restored_state:
            try:
                return float(self._restored_state.state)
            except (ValueError, TypeError):
                pass
        return None


class PsegNextUpdateSensor(PsegBaseSensor):
    """Sensor for the next scheduled data update timestamp."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_icon = "mdi:clock-outline"

    def __init__(self, coordinator: PsegDataUpdateCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "next_update")

    @property
    def native_value(self) -> datetime | None:
        """Return the next scheduled update time as a timezone-aware datetime."""
        if self.coordinator.next_update_time:
            return self.coordinator.next_update_time
        if self._restored_state:
            try:
                return dt_util.parse_datetime(self._restored_state.state)
            except Exception:
                pass
        return None
