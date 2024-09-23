import asyncio
import pytest
from whisper.api import Bzsp
from whisper.bzsp.types import BzspValueId
from whisper.bzsp.types import BzspApsFrameHeader, NetworkState, Status
from whisper.zigbee.application import ControllerApplication
from zigpy.config import CONF_DEVICE_PATH
import zigpy.config
import zigpy.types as t
import logging

@pytest.fixture
async def bzsp_instance():
    device_config =   {
            zigpy.config.CONF_DEVICE: {
                zigpy.config.CONF_DEVICE_PATH: "COM20",
                zigpy.config.CONF_DEVICE_BAUDRATE: 2000000,
            }
        }
    app = ControllerApplication(device_config)
    bzsp = Bzsp(app, device_config[zigpy.config.CONF_DEVICE])
    await bzsp.connect()
    yield bzsp
    await asyncio.sleep(12)  # Wait for 10 seconds before releasing the bzsp object
    bzsp.close()


@pytest.mark.asyncio
async def test_connect_to_ncp(bzsp_instance):
    async for bzsp in bzsp_instance:
        assert bzsp.network_state != NetworkState.OFFLINE


@pytest.mark.asyncio
async def test_form_zigbee_network(bzsp_instance):
    async for bzsp in bzsp_instance:
        status = await bzsp.form_network(ext_pan_id=t.uint64_t(0x1234567890abcdef), pan_id=t.uint16_t(0x1234), channel=t.uint8_t(15))
        assert status == Status.SUCCESS

# only test the case when the network is already formed but it will not wait until the permit joining is done
@pytest.mark.asyncio
async def test_permit_joining(bzsp_instance):
    async for bzsp in bzsp_instance:
        await bzsp.form_network(ext_pan_id=t.uint64_t(0x1234567890abcdef), pan_id=t.uint16_t(0x1234), channel=t.uint8_t(15))
        status = await bzsp.permit_joining(duration=t.uint8_t(10))
        assert status == Status.SUCCESS


@pytest.mark.asyncio
async def test_send_aps_data(bzsp_instance):
    async for bzsp in bzsp_instance:
        status = await bzsp.form_network(ext_pan_id=t.uint64_t(0x1234567890abcdef), pan_id=t.uint16_t(0x1234), channel=t.uint8_t(15))
        aps_frame = BzspApsFrameHeader(
            msg_type=0x00,
            dst_short_addr=0x5678,
            profile_id=0x0104,
            cluster_id=0x0006,
            src_ep=1,
            dst_ep=1
        )
        status = await bzsp.send_aps_data(aps_frame, asdu=b'\x01\x02\x03')
        assert status == Status.SUCCESS


@pytest.mark.asyncio
async def test_leave_network(bzsp_instance):
    async for bzsp in bzsp_instance:
        await bzsp.form_network(ext_pan_id=t.uint64_t(0x1234567890abcdef), pan_id=t.uint16_t(0x1234), channel=t.uint8_t(15))
        status = await bzsp.leave_network()
        assert status == Status.SUCCESS


@pytest.mark.asyncio
async def test_get_network_info(bzsp_instance):
    async for bzsp in bzsp_instance:
        status = await bzsp.form_network(ext_pan_id=t.uint64_t(0x1234567890abcdef), pan_id=t.uint16_t(0x1234), channel=t.uint8_t(15))
        await asyncio.sleep(5)
        network_info = await bzsp.get_network_info()
        assert network_info["pan_id"] == 0x1234
        assert network_info["channel"] == 15


@pytest.mark.asyncio
async def test_get_bzsp_version(bzsp_instance):
    """Test getting the BZSP version."""
    async for bzsp in bzsp_instance:
        version = await bzsp.get_bzsp_version()
        assert version == 1

@pytest.mark.asyncio
async def test_get_stack_version(bzsp_instance):
    """Test getting the Zigbee stack version."""
    async for bzsp in bzsp_instance:
        stack_version = await bzsp.get_stack_version()
        assert stack_version["major"] >= 0
        assert stack_version["minor"] >= 0
        assert stack_version["patch"] >= 0
        assert stack_version["build"] >= 0

@pytest.mark.asyncio
async def test_get_neighbor_table_size(bzsp_instance):
    """Test getting the neighbor table size."""
    async for bzsp in bzsp_instance:
        neighbor_table_size = await bzsp.get_neighbor_table_size()
        assert neighbor_table_size > 0

@pytest.mark.asyncio
async def test_get_source_route_table_size(bzsp_instance):
    """Test getting the source route table size."""
    async for bzsp in bzsp_instance:
        source_route_table_size = await bzsp.get_source_route_table_size()
        assert source_route_table_size > 0

@pytest.mark.asyncio
async def test_get_route_table_size(bzsp_instance):
    """Test getting the routing table size."""
    async for bzsp in bzsp_instance:
        route_table_size = await bzsp.get_route_table_size()
        assert route_table_size > 0

@pytest.mark.asyncio
async def test_get_address_table_size(bzsp_instance):
    """Test getting the address map table size."""
    async for bzsp in bzsp_instance:
        address_table_size = await bzsp.get_address_table_size()
        assert address_table_size > 0

@pytest.mark.asyncio
async def test_get_broadcast_table_size(bzsp_instance):
    """Test getting the broadcast table size."""
    async for bzsp in bzsp_instance:
        broadcast_table_size = await bzsp.get_broadcast_table_size()
        assert broadcast_table_size > 0

@pytest.mark.asyncio
async def test_get_trust_center_address(bzsp_instance):
    """Test getting the Trust Center address."""
    async for bzsp in bzsp_instance:
        trust_center_address = await bzsp.get_trust_center_address()
        assert trust_center_address is not None
        assert isinstance(trust_center_address, t.EUI64)

@pytest.mark.asyncio
async def test_get_unique_tc_link_key_table_size(bzsp_instance):
    """Test getting the unique TC link key table size."""
    async for bzsp in bzsp_instance:
        tc_link_key_table_size = await bzsp.get_unique_tc_link_key_table_size()
        assert tc_link_key_table_size == 0

@pytest.mark.asyncio
async def test_get_mac_address(bzsp_instance):
    """Test getting the MAC address of the NCP."""
    async for bzsp in bzsp_instance:
        mac_address = await bzsp.get_mac_address()
        assert mac_address is not None
        assert isinstance(mac_address, t.EUI64)

@pytest.mark.asyncio
async def test_get_app_version(bzsp_instance):
    """Test getting the application version of the NCP."""
    async for bzsp in bzsp_instance:
        app_version = await bzsp.get_app_version()
        assert app_version is not None
        assert isinstance(app_version, str)


@pytest.mark.asyncio
async def test_add_endpoint(bzsp_instance):
    async for bzsp in bzsp_instance:
        status = await bzsp.add_endpoint(t.uint8_t(1), t.uint16_t(0x0104), t.uint16_t(0x0006), [t.uint16_t(0x0006)], [t.uint16_t(0x0008)])
        assert status == Status.SUCCESS

@pytest.mark.asyncio
async def test_get_network_payload_limit(bzsp_instance):
    async for bzsp in bzsp_instance:
        payload_limit = await bzsp.get_network_payload_limit(t.uint16_t(0x5678))
        assert payload_limit > 0

@pytest.mark.asyncio
async def test_get_network_security_infos(bzsp_instance):
    async for bzsp in bzsp_instance:
        security_info = await bzsp.get_network_security_infos()
        assert security_info["nwk_key"] is not None


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(pytest.main(["-s", __file__]))