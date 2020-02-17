// Copyright 2020 Shift Cryptosecurity AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use futures::prelude::*;
use hidapi::HidApi;
use hidapi_async::Device;

fn main() {
    let api = HidApi::new().unwrap();
    let device = api.open(0x03eb, 0x2403).unwrap();

    let mut device = Device::new(device);

    let mut rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        // First byte is 0 because device doesn't use report ids
        let cmd = [0u8; 65];
        device.write(&cmd[..]).await.unwrap();

        // Does not contain report id since device doesn't use them
        let mut buf = [0u8; 64];
        let len = device.read(&mut buf).await.unwrap();
        println!("{:?}", &buf[..len]);
    })
}
