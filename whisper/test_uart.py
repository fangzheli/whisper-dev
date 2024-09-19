import asyncio
import binascii
from unittest import mock
import pytest
import pytest_asyncio

from uart import BzspUartGateway, connect


@pytest_asyncio.fixture
async def uart_gateway():
    api = mock.Mock()
    connected_future = asyncio.get_running_loop().create_future()
    gateway = BzspUartGateway(api, connected_future)
    return gateway, api, connected_future


@pytest.mark.asyncio
async def test_connection_made(uart_gateway):
    gateway, api, connected_future = uart_gateway

    # Simulate connection being made
    transport = mock.Mock()
    gateway.connection_made(transport)

    # Check if the connection future is resolved
    assert connected_future.done()
    assert connected_future.result() is True
    assert gateway._transport is transport


@pytest.mark.asyncio
async def test_data_received(uart_gateway):
    gateway, api, _ = uart_gateway

    # Simulate receiving a properly framed and valid CRC data packet
    data = binascii.unhexlify("42010002456A9C4C")  # Example frame with start, data, and stop byte

    gateway.data_received(data)

    # Verify that the data was passed to the API's `data_received` method
    api.data_received.assert_called_once_with(b"\x00\x02\x45")


@pytest.mark.asyncio
async def test_data_received_invalid_crc(uart_gateway):
    gateway, api, _ = uart_gateway

    # Simulate receiving a frame with invalid CRC
    data = binascii.unhexlify("42010002FFFF4C")  # Example frame with invalid CRC

    gateway.data_received(data)

    # Ensure the data was not passed to the API due to CRC failure
    api.data_received.assert_not_called()


@pytest.mark.asyncio
async def test_send_data(uart_gateway):
    gateway, api, _ = uart_gateway

    # Mock the transport write method
    transport = mock.Mock()
    gateway._transport = transport

    # Data to send
    data_to_send = b"\x00\x01\x02"
    gateway.send(data_to_send)

    # Ensure the correct framed data is sent through the transport
    expected_crc = gateway._compute_crc(data_to_send)
    expected_frame = gateway._escape_frame(data_to_send + expected_crc)
    expected_output = gateway.START_BYTE + expected_frame + gateway.STOP_BYTE

    transport.write.assert_called_once_with(expected_output)
