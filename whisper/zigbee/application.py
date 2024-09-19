"""ControllerApplication for BouffaloLab BZSP protocol based adapters."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import zigpy.application
import zigpy.config
import zigpy.device
import zigpy.state
import zigpy.types as t
import zigpy.zdo.types as zdo_t
import zigpy.util
import importlib.metadata

from whisper.api import Bzsp
from whisper.bzsp.types import NetworkState, Status
import whisper.exception

LOGGER = logging.getLogger(__name__)

CHANGE_NETWORK_POLL_TIME = 1
CHANGE_NETWORK_STATE_DELAY = 2
DELAY_NEIGHBOUR_SCAN_S = 1500
SEND_CONFIRM_TIMEOUT = 60


class ControllerApplication(zigpy.application.ControllerApplication):
    """ControllerApplication for BouffaloLab BZSP protocol based adapters."""
    _probe_config_variants = [
        {zigpy.config.CONF_DEVICE_BAUDRATE: 2000000},
    ]

    _watchdog_period = 600 * 0.75

    def __init__(self, config: dict[str, Any]):
        """Initialize instance."""
        super().__init__(config=zigpy.config.ZIGPY_SCHEMA(config))
        self._api = None

        self._pending = zigpy.util.Requests()

        self._delayed_neighbor_scan_task = None
        self._reconnect_task = None

        self._written_endpoints = set()

    async def _watchdog_feed(self):
        await self._api.set_watchdog_ttl(int(self._watchdog_period / 0.75))

    async def connect(self):
        api = Bzsp(self, self._config[zigpy.config.CONF_DEVICE])

        try:
            await api.connect()
        except Exception:
            api.close()
            raise

        self._api = api
        self._written_endpoints.clear()

    async def disconnect(self):
        if self._delayed_neighbor_scan_task is not None:
            self._delayed_neighbor_scan_task.cancel()
            self._delayed_neighbor_scan_task = None

        if self._api is not None:
            self._api.close()
            self._api = None

    async def permit_with_link_key(self, node: t.EUI64, link_key: t.KeyData, time_s=60):
        await self._api.set_unique_tc_link_key(
            node, link_key
        )
        await self.permit(time_s)

    async def start_network(self):
        await self.register_endpoints()
        await self.load_network_info(load_devices=False)
        await self._change_network_state(NetworkState.CONNECTED)

        coordinator = await BzspDevice.new(
            self,
            self.state.node_info.ieee,
            self.state.node_info.nwk,
            self.state.node_info.model,
        )

        self.devices[self.state.node_info.ieee] = coordinator

        self._delayed_neighbor_scan_task = asyncio.create_task(
            self._delayed_neighbour_scan()
        )

    async def _change_network_state(
        self,
        target_state: NetworkState,
        *,
        timeout: int = 10 * CHANGE_NETWORK_POLL_TIME,
    ):
        async def change_loop():
            while True:
                try:
                    device_state = await self._api.get_device_state()
                except asyncio.TimeoutError:
                    LOGGER.debug("Failed to poll device state")
                else:
                    if NetworkState(device_state.network_state) == target_state:
                        break

                await asyncio.sleep(CHANGE_NETWORK_POLL_TIME)

        await self._api.change_network_state(target_state)

        try:
            async with asyncio_timeout(timeout):
                await change_loop()
        except asyncio.TimeoutError:
            if target_state != NetworkState.CONNECTED:
                raise

            raise zigpy.exceptions.FormationFailure("Network formation refused.")

    async def reset_network_info(self):
        await self.form_network()

    async def write_network_info(self, *, network_info, node_info):
        try:
            await self._api.set_nwk_frame_counter(network_info.network_key.tx_counter)
        except whisper.bzsp.exception.CommandError as ex:
            assert ex.status == Status.UNSUPPORTED
            LOGGER.warning(
                "Doesn't support writing the network frame counter with this firmware"
            )

        # if node_info.logical_type == zdo_t.LogicalType.Coordinator:
        #     await self._api.set_aps_designed_coordinator(1)
        # else:
        #     await self._api.set_aps_designed_coordinator(0)

        await self._api.set_nwk_address(node_info.nwk)

        if node_info.ieee != t.EUI64.UNKNOWN:
            await self._api.set_mac_address(node_info.ieee)
            node_ieee = node_info.ieee
        else:
            ieee = await self._api.get_mac_address()
            node_ieee = t.EUI64(ieee)

        if network_info.channel is not None:
            channel_mask = t.Channels.from_channel_list(
                [network_info.channel]
            )

            if network_info.channel_mask and channel_mask != network_info.channel_mask:
                LOGGER.warning(
                    "Channel mask %s will be replaced with current logical channel %s",
                    network_info.channel_mask,
                    channel_mask,
                )
        else:
            channel_mask = network_info.channel_mask

        await self._api.set_channel_mask(channel_mask)
        await self._api.set_use_predefined_nwk_panid(True)
        await self._api.set_nwk_panid(network_info.pan_id)
        await self._api.set_aps_extended_panid(network_info.extended_pan_id)
        await self._api.set_nwk_update_id(network_info.nwk_update_id)

        await self._api.set_network_key(
            network_info.network_key.key,
        )

        if network_info.network_key.seq != 0:
            LOGGER.warning(
                "Doesn't support non-zero network key sequence number: %s",
                network_info.network_key.seq,
            )

        tc_link_key_partner_ieee = network_info.tc_link_key.partner_ieee

        if tc_link_key_partner_ieee == t.EUI64.UNKNOWN:
            tc_link_key_partner_ieee = node_ieee

        await self._api.set_trust_center_address(
            tc_link_key_partner_ieee,
        )
        await self._api.set_link_key(
            tc_link_key_partner_ieee,
            network_info.tc_link_key.key,
        )

        if network_info.security_level == 0x00:
            await self._api.set_security_mode(t.SecurityMode.NO_SECURITY)
        else:
            await self._api.set_security_mode(t.SecurityMode.ONLY_TCLK)

        await self._change_network_state(NetworkState.OFFLINE)
        await asyncio.sleep(CHANGE_NETWORK_STATE_DELAY)
        await self._change_network_state(NetworkState.CONNECTED)

    async def load_network_info(self, *, load_devices=False):
        network_info = self.state.network_info
        node_info = self.state.node_info

        ieee = await self._api.get_mac_address()
        node_info.ieee = t.EUI64(ieee)
        nwk_info = await self._api.get_network_info()
        if nwk_info["node_type"] == 0x00:
            node_info.logical_type = zdo_t.LogicalType.Coordinator
            node_info.nwk = t.NWK(0x0000)
        else:
            node_info.logical_type = zdo_t.LogicalType.Router

        node_info.manufacturer = "Bouffalo Lab"

        node_info.model = "BL706"

        node_info.version = f"{int(self._api.firmware_version):#010x}"

        network_info.source = f"whisper@{importlib.metadata.version('whisper')}"
        network_info.metadata = {
            "bzsp": {
                "version": node_info.version,
            }
        }

        network_info.pan_id = nwk_info["pan_id"]
        network_info.extended_pan_id = nwk_info["ext_pan_id"]

        network_info.channel = nwk_info["channel"]
        network_info.channel_mask = t.Channels(nwk_info["channel_mask"])
        network_info.nwk_update_id = nwk_info["nwk_update_id"]

        if network_info.channel == 0:
            raise zigpy.exceptions.NetworkNotFormed("Network channel is zero")

        security_info = await self._api.get_security_infos()

        network_info.network_key = zigpy.state.Key()
        network_info.network_key.key = security_info["nwk_key"]
        network_info.network_key.seq = security_info["nwk_key_seq_num"]
        network_info.network_key.tx_counter = security_info["outgoing_frame_counter"]


        network_info.tc_link_key = zigpy.state.Key()
        network_info.tc_link_key.partner_ieee = await self._api.get_trust_center_address()

        link_key = await self._api.get_unique_tc_link_key(
            network_info.tc_link_key.partner_ieee,
        )
        network_info.tc_link_key.key = link_key['link_key']

        # security mode

    async def force_remove(self, dev):
        """Forcibly remove device from NCP."""
        pass

    async def energy_scan(
        self, channels: t.Channels, duration_exp: int, count: int
    ) -> dict[int, float]:
        results = await super().energy_scan(
            channels=channels, duration_exp=duration_exp, count=count
        )

        return {c: v * 3 for c, v in results.items()}

    async def add_endpoint(self, descriptor: zdo_t.SimpleDescriptor) -> None:
        """Register a new endpoint on the device."""

        await self._api.add_endpoint(
            endpoint=descriptor.endpoint,
            profile_id=descriptor.profile,
            device_id=descriptor.device_type,
            app_flags=descriptor.device_version,
            input_clusters=descriptor.input_clusters,
            output_clusters=descriptor.output_clusters,
        )

    async def send_packet(self, packet):
        LOGGER.debug("Sending packet: %r", packet)

        force_relays = None

        dst_addr = packet.dst.address
        addr_mode = packet.dst.addr_mode
        if packet.dst.addr_mode != t.AddrMode.IEEE:
            dst_addr = t.EUI64(
                [
                    packet.dst.address % 0x100,
                    packet.dst.address >> 8,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]
            )
        if packet.dst.addr_mode == t.AddrMode.Broadcast:
            addr_mode = t.AddrMode.Group

        if packet.dst.addr_mode != t.AddrMode.IEEE:
            src_addr = t.EUI64(
                [
                    packet.dst.address % 0x100,
                    packet.dst.address >> 8,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]
            )

        if packet.source_route is not None:
            force_relays = packet.source_route

        tx_options = t.BzspTransmitOptions.NONE

        if t.TransmitOptions.ACK in packet.tx_options:
            tx_options |= t.BzspTransmitOptions.ACK_ENABLED

        if t.TransmitOptions.APS_Encryption in packet.tx_options:
            tx_options |= t.BzspTransmitOptions.SECURITY_ENABLED

        async with self._limit_concurrency():
            await self._api.aps_data_request(
                dst_addr=dst_addr,
                dst_ep=packet.dst_ep,
                src_addr=src_addr,
                src_ep=packet.src_ep,
                profile=packet.profile_id,
                addr_mode=addr_mode,
                cluster=packet.cluster_id,
                sequence=packet.tsn,
                options=tx_options,
                radius=packet.radius or 0,
                data=packet.data.serialize(),
                relays=force_relays,
                extended_timeout=packet.extended_timeout,
            )

    async def permit_ncp(self, time_s=60):
        assert 0 <= time_s <= 254
        await self._api.permit_joining(time_s)


    async def _delayed_neighbour_scan(self) -> None:
        """Scan coordinator's neighbours."""
        await asyncio.sleep(DELAY_NEIGHBOUR_SCAN_S)
        coord = self.get_device(ieee=self.state.node_info.ieee)
        await self.topology.scan(devices=[coord])


class BzspDevice(zigpy.device.Device):
    """Zigpy Device representing Coordinator."""

    def __init__(self, model: str, *args):
        """Initialize instance."""

        super().__init__(*args)
        self._model = model

    async def add_to_group(self, grp_id: int, name: str = None) -> None:
        group = self.application.groups.add_group(grp_id, name)

        for epid in self.endpoints:
            if not epid:
                continue  # skip ZDO
            group.add_member(self.endpoints[epid])
        return [0]

    async def remove_from_group(self, grp_id: int) -> None:
        for epid in self.endpoints:
            if not epid:
                continue  # skip ZDO
            self.application.groups[grp_id].remove_member(self.endpoints[epid])
        return [0]

    @property
    def manufacturer(self):
        return "Bouffalo Lab"

    @property
    def model(self):
        return self._model

    @classmethod
    async def new(cls, application, ieee, nwk, model: str):
        """Create or replace zigpy device."""
        dev = cls(model, application, ieee, nwk)

        if ieee in application.devices:
            from_dev = application.get_device(ieee=ieee)
            dev.status = from_dev.status
            dev.node_desc = from_dev.node_desc
            for ep_id, from_ep in from_dev.endpoints.items():
                if not ep_id:
                    continue  # Skip ZDO
                ep = dev.add_endpoint(ep_id)
                ep.profile_id = from_ep.profile_id
                ep.device_type = from_ep.device_type
                ep.status = from_ep.status
                ep.in_clusters = from_ep.in_clusters
                ep.out_clusters = from_ep.out_clusters
        else:
            application.devices[ieee] = dev
            await dev.initialize()

        return dev
