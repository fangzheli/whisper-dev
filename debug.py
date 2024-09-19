import whisper.zigbee.application
import zigpy.config
import asyncio
import logging

async def test_main():
    app = whisper.zigbee.application.ControllerApplication(
        {
                zigpy.config.CONF_DEVICE: {
                    zigpy.config.CONF_DEVICE_PATH: "COM20",
                    zigpy.config.CONF_DEVICE_BAUDRATE: 2000000,
                }
            }
        )
    await app.connect()
    print("Connected to the device")

# Run the main test function using asyncio
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(test_main())