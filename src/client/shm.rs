// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! wprsc's side of xen_shm: the granted buffers of wprsd's domain, mapped
//! read-only through dom0's broker for that domain (see server/shm.rs).

use std::collections::HashMap;
use std::path::Path;

use crate::prelude::*;
use crate::serialization::wayland::ShmBuffer;
use crate::serialization::wayland::ShmSlot;
use crate::xen_shm::GrantMap;
use crate::xen_shm::MappedBuffer;

#[derive(Debug)]
pub struct ShmClient {
    map: GrantMap,
    buffers: HashMap<ShmSlot, MappedBuffer>,
}

impl ShmClient {
    pub fn new(socket: &Path) -> Result<Self> {
        Ok(Self {
            map: GrantMap::connect(socket).location(loc!())?,
            buffers: HashMap::new(),
        })
    }

    pub fn add(&mut self, buffer: ShmBuffer) -> Result<()> {
        let mapped = self.map.map(&buffer.refs).location(loc!())?;
        self.buffers.insert(buffer.id, mapped);
        Ok(())
    }

    pub fn release(&mut self, id: ShmSlot) {
        self.buffers.remove(&id);
    }

    pub fn get(&self, id: ShmSlot) -> Option<&MappedBuffer> {
        self.buffers.get(&id)
    }
}
