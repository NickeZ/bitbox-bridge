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

//! This crate provides an async abstraction over hidapi.
//!
//! This library will spawn one thread per connected device.
//!
//! # Usage
//!
//! ```rust,no_run
//! use hidapi::HidApi;
//! fn main() {
//!    let api = HidApi::new().unwrap();
//!    let device = api.open(...);
//!
//!    let device = Device::new(device);
//!
//!    rt.block_on(async {
//!        let cmd = [0u8; 65];
//!        device.write(&cmd[..]).await;
//!        let buf = [0u8; 64];
//!        let len = device.read(&buf).await();
//!        println!("{}", buf[..len]);
//!    })
//! }
//! ```

#[macro_use]
extern crate log;

use futures::prelude::*;
use futures::task::SpawnError;
use hidapi::{HidDevice, HidError};
use std::io;
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("libhid failed")]
    HidApi(#[from] HidError),
    #[error("io failed")]
    Io(#[from] io::Error),
    #[error("spawn failed")]
    Spawn(#[from] SpawnError),
}

enum ReadState {
    Idle,
    Busy,
}

pub struct Device {
    // store an Option so that `close` can drop the HidDevice.
    device: Option<HidDevice>,
    rstate: ReadState,
    buffer: Option<[u8; 64]>,
    buffer_pos: usize,
}

impl Clone for Device {
    fn clone(&self) -> Self {
        Device {
            inner: self.inner.as_ref().map(|dev| Arc::clone(&dev)),
        }
    }
}

impl Device {
    pub fn new(device: HidDevice) -> Self {
        device.set_blocking_mode(false);
        // Must be accessed from both inner thread and asyn_write
        Device {
                Some(device),
                rstate: ReadState::Idle,
                buffer: None,
                buffer_pos: 0,
        }
    }
}

/// See [HidDevice] for details regarding report id.
impl AsyncWrite for Device {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context,
        mut buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let len = buf.len();
        if self.inner.is_none() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cannot poll a closed device",
            )));
        }
        loop {
            debug!("Will write {:?}", &buf[..]);
            // TODO: Could this write block, and what to do then?
            let len = self.inner.as_mut().unwrap().write(&buf[..])
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "hidapi failed"))?;
            buf = &buf[len..];
            if buf.len() == 0 {
                debug!("Wrote total {}: {:?}", buf.len(), buf);
                return Poll::Ready(Ok(len));
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), io::Error>> {
        // libhidapi doesn't have a concept of flush
        Poll::Ready(Ok(()))
    }
    // TODO cleanup read thread...
    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let this: &mut Self = &mut self;
        // take the device and drop it
        let _device = this.inner.take();
        Poll::Ready(Ok(()))
    }
}

// Will always read out 64 bytes. Make sure to read out all bytes to avoid trailing bytes in next
// readout.
// Will store all bytes that did not fit in provided buffer and give them next time.
/// See [HidDevice] for details regarding report id.
impl AsyncRead for Device {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.inner.is_none() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cannot poll a closed device",
            )));
        }
        let mut this =
            self.inner.as_mut().unwrap().lock().map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Mutex broken: {:?}", e))
            })?;
        loop {
            let waker = cx.waker().clone();
            match this.rstate {
                ReadState::Idle => {
                    debug!("Sending waker");
                    if let Some(req_tx) = &mut this.req_tx {
                        if let Err(_e) = req_tx.send(waker) {
                            error!("failed to send waker");
                        }
                    } else {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Failed internal send",
                        )));
                    }
                    this.rstate = ReadState::Busy;
                }
                ReadState::Busy => {
                    // First send any bytes from the previous readout
                    if let Some(inner_buf) = this.buffer.take() {
                        let len = usize::min(buf.len(), inner_buf.len());
                        let inner_slice = &inner_buf[this.buffer_pos..this.buffer_pos + len];
                        let buf_slice = &mut buf[..len];
                        buf_slice.copy_from_slice(inner_slice);
                        // Check if there is more data left
                        if this.buffer_pos + inner_slice.len() < inner_buf.len() {
                            this.buffer = Some(inner_buf);
                            this.buffer_pos += inner_slice.len();
                        } else {
                            this.rstate = ReadState::Idle;
                        }
                        return Poll::Ready(Ok(len));
                    }

                    // Second try to receive more bytes
                    let vec = match this.data_rx.try_recv() {
                        Ok(Some(vec)) => vec,
                        Ok(None) => {
                            // end of stream?
                            return Poll::Pending;
                        }
                        Err(e) => match e {
                            mpsc::TryRecvError::Disconnected => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("Inner channel dead"),
                                )));
                            }
                            mpsc::TryRecvError::Empty => {
                                return Poll::Pending;
                            }
                        },
                    };
                    debug!("Read data {:?}", &vec[..]);
                    let len = usize::min(vec.len(), buf.len());
                    let buf_slice = &mut buf[..len];
                    let vec_slice = &vec[..len];
                    buf_slice.copy_from_slice(vec_slice);
                    if len < vec.len() {
                        // If bytes did not fit in buf, store bytes for next readout
                        this.buffer = Some(vec);
                        this.buffer_pos = 0;
                    } else {
                        this.rstate = ReadState::Idle;
                    }
                    debug!("returning {}", len);
                    return Poll::Ready(Ok(len));
                }
            };
        }
                loop {
                    // Wait for read request
                    debug!("waiting for request");
                    let waker = match req_rx.recv() {
                        Ok(waker) => waker,
                        Err(_e) => {
                            info!("No more wakers, shutting down");
                            return;
                        }
                    };
                    debug!("Got notified");
                    match device.lock() {
                        Ok(guard) => {
                            let mut buf = [0u8; 64];
                            //match guard.read_timeout(&mut buf[..], 1000) {
                            match guard.read(&mut buf[..]) {
                                Err(e) => {
                                    error!("hidapi failed: {}", e);
                                    drop(data_tx);
                                    waker.wake_by_ref();
                                    break;
                                }
                                Ok(len) => {
                                    if len == 0 {
                                        data_tx.send(None).unwrap();
                                        waker.wake_by_ref();
                                        continue;
                                    }
                                    debug!("Read data");
                                    if let Err(e) = data_tx.send(Some(buf)) {
                                        error!("Sending internally: {}", e);
                                        break;
                                    }
                                    waker.wake_by_ref();
                                }
                            }
                        }
                        Err(e) => {
                            error!("Broken lock: {:?}", e);
                            return;
                        }
                    }
                }
            }
    }
}
