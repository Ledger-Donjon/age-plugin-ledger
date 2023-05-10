use hidapi::{DeviceInfo, HidApi, HidDevice, HidError};

pub struct LedgerHIDDevice {
    device: HidDevice,
}

impl LedgerHIDDevice {
    pub fn new() -> Self {
        let api = HidApi::new().unwrap();
        let ledger_devices: Vec<&DeviceInfo> = api
            .device_list()
            .filter(|d| d.vendor_id() == 0x2c97)
            .collect();
        if ledger_devices.len() < 1 {
            panic!("no Ledger Nano were found");
        }
        let device = ledger_devices[0].open_device(&api).unwrap();
        device.set_blocking_mode(true).unwrap();

        LedgerHIDDevice { device }
    }

    pub fn exchange(&self, data: &[u8]) -> Result<Vec<u8>, HidError> {
        let mut buffer = [0u8; 65];
        let header = [0x00, 0x01, 0x01, 0x05];
        let data_len = (data.len() as u16).to_be_bytes();
        let mut data_to_send = data_len.to_vec();
        data_to_send.extend_from_slice(data);
        for (seq_idx, packet) in data_to_send.chunks(64-5).enumerate() {
            buffer[0..][..header.len()].copy_from_slice(&header);
            buffer[header.len()..][..2].copy_from_slice(&(seq_idx as u16).to_be_bytes());
            buffer[header.len() + 2..][..packet.len()].copy_from_slice(packet);

            let packet_length = packet.len() + 2 + header.len();
            self.device.write(&buffer[..packet_length])?;
        }

        let read_len = self.device.read(&mut buffer)?;
        let expected_length = u16::from_be_bytes([buffer[5], buffer[6]]) as usize;
        let mut res = Vec::from(&buffer[7..][..expected_length.min(read_len - 7)]);

        let mut total_read = expected_length.min(read_len - 7);
        while total_read < expected_length {
            let read_len = self.device.read_timeout(&mut buffer, 1000)?;
            res.extend_from_slice(&buffer[5..][..(expected_length - total_read).min(read_len - 5)]);
            total_read += expected_length.min(read_len - 5);
        }

        Ok(res)
    }
}
