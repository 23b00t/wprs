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

//! wprsd's side of xen_shm: two granted buffers per surface. A commit copies
//! its pixels into the next one and only sends the buffer's id; wprsc copies
//! them out and acks, then the buffer may be written again. While it isn't
//! acked yet, the commit goes over the stream as before.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use smithay::wayland::compositor::SurfaceData;
use smithay::wayland::shm::BufferData as SmithayBufferData;

use crate::buffer_pointer::BufferPointer;
use crate::filtering;
use crate::prelude::*;
use crate::serialization::Request;
use crate::serialization::geometry::Rectangle;
use crate::serialization::wayland::BufferMetadata;
use crate::serialization::wayland::ShmBuffer;
use crate::serialization::wayland::ShmSlot;
use crate::sharding_compression::CompressedShards;
use crate::sharding_compression::ShardingCompressor;
use crate::xen_shm;
use crate::xen_shm::GrantAlloc;
use crate::xen_shm::SharedBuffer;

// More damage rectangles than this pending for a buffer: copy all of it.
const MAX_PENDING_DAMAGE: usize = 32;
// After a failed allocation: new buffers over the stream for this long.
const RETRY_ALLOC: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct ShmServer {
    alloc: GrantAlloc,
    busy: Arc<Mutex<HashSet<ShmSlot>>>,
    next_id: u64,
    // Buffers of an earlier epoch were announced to an earlier wprsc.
    epoch: u64,
    // After a failed allocation, new buffers wait until then.
    retry_after: Option<Instant>,
}

#[derive(Debug)]
struct Slot {
    id: ShmSlot,
    buf: SharedBuffer,
    // Damage since this buffer was last written, None: all of it.
    damage: Option<Vec<Rectangle<i32>>>,
}

#[derive(Debug)]
struct ShmSurface {
    epoch: u64,
    metadata: BufferMetadata,
    slots: [Slot; 2],
    next: usize,
}

/// In the surface's data map.
#[derive(Debug, Default)]
pub struct ShmSurfaceCell(Mutex<Option<ShmSurface>>);

impl ShmServer {
    pub fn new(epoch: u64, socket: &Path) -> Result<Self> {
        Ok(Self {
            alloc: GrantAlloc::connect(socket).location(loc!())?,
            busy: Arc::new(Mutex::new(HashSet::new())),
            next_id: 0,
            epoch,
            retry_after: None,
        })
    }

    pub fn ack(&self, id: ShmSlot) {
        self.busy.lock().unwrap().remove(&id);
    }

    /// The surface's next buffer is still waiting for wprsc's ack.
    pub fn next_busy(&self, surface_data: &SurfaceData) -> bool {
        let Some(cell) = surface_data.data_map.get::<ShmSurfaceCell>() else {
            return false;
        };
        let guard = cell.0.lock().unwrap();
        guard.as_ref().is_some_and(|surf| {
            surf.epoch == self.epoch
                && self
                    .busy
                    .lock()
                    .unwrap()
                    .contains(&surf.slots[surf.next].id)
        })
    }

    fn allocate(&mut self, metadata: BufferMetadata) -> Result<ShmSurface> {
        let len = xen_shm::image_len(metadata.stride, metadata.width, metadata.height)
            .location(loc!())?;
        let mut share = || -> Result<Slot> {
            let buf = self.alloc.share(len).location(loc!())?;
            self.next_id += 1;
            Ok(Slot {
                id: ShmSlot(self.next_id),
                buf,
                damage: None,
            })
        };
        Ok(ShmSurface {
            epoch: self.epoch,
            metadata,
            slots: [share()?, share()?],
            next: 0,
        })
    }

    fn forget(&self, surf: ShmSurface, out: &mut Vec<Request>) {
        if surf.epoch != self.epoch {
            return;
        }
        let mut busy = self.busy.lock().unwrap();
        for slot in &surf.slots {
            busy.remove(&slot.id);
            out.push(Request::ShmRelease(slot.id));
        }
    }

    /// Copies a committed buffer into the surface's next granted buffer.
    /// Returns the messages to send first and the buffer to commit with, None:
    /// send the pixels over the stream.
    pub fn commit(
        &mut self,
        surface_data: &SurfaceData,
        spec: &SmithayBufferData,
        data: BufferPointer<u8>,
        damage: &[Rectangle<i32>],
    ) -> Result<(Vec<Request>, Option<(BufferMetadata, ShmSlot)>)> {
        let mut out = Vec::new();
        let metadata = BufferMetadata::from_buffer_data(spec).location(loc!())?;
        surface_data
            .data_map
            .insert_if_missing_threadsafe(ShmSurfaceCell::default);
        let cell = surface_data
            .data_map
            .get::<ShmSurfaceCell>()
            .location(loc!())?;
        let mut guard = cell.0.lock().unwrap();

        let stale = guard
            .as_ref()
            .is_none_or(|surf| surf.epoch != self.epoch || surf.metadata != metadata);
        if stale {
            if let Some(old) = guard.take() {
                self.forget(old, &mut out);
            }
            if self.retry_after.is_some_and(|t| Instant::now() < t) {
                return Ok((out, None));
            }
            match self.allocate(metadata) {
                Ok(surf) => {
                    for slot in &surf.slots {
                        out.push(Request::ShmBuffer(ShmBuffer {
                            id: slot.id,
                            refs: slot.buf.refs.clone(),
                        }));
                    }
                    *guard = Some(surf);
                    self.retry_after = None;
                },
                Err(e) => {
                    // Most likely the gntalloc limit (grants left for the
                    // VM's devices) or the broker is gone: this surface stays
                    // on the stream, the next new buffer tries again later.
                    warn!("granting buffers failed, sending pixels over the stream: {e:?}");
                    self.retry_after = Some(Instant::now() + RETRY_ALLOC);
                    return Ok((out, None));
                },
            }
        }
        let surf = guard.as_mut().location(loc!())?;

        for slot in &mut surf.slots {
            if let Some(pending) = &mut slot.damage {
                pending.extend_from_slice(damage);
                if pending.len() > MAX_PENDING_DAMAGE {
                    slot.damage = None;
                }
            }
        }

        let slot = &mut surf.slots[surf.next];
        let mut busy = self.busy.lock().unwrap();
        if busy.contains(&slot.id) {
            return Ok((out, None));
        }
        let len = xen_shm::image_len(metadata.stride, metadata.width, metadata.height)
            .location(loc!())?;
        if data.len() < len || slot.buf.len() < len {
            bail!("buffer smaller than {len} bytes");
        }
        // SAFETY: both are at least image_len bytes (checked above).
        unsafe {
            xen_shm::copy_rects(
                data.ptr(),
                slot.buf.as_mut_ptr(),
                metadata.stride as usize,
                metadata.width,
                metadata.height,
                slot.damage.as_deref(),
            );
        }
        slot.damage = Some(Vec::new());
        busy.insert(slot.id);
        let id = slot.id;
        surf.next ^= 1;
        Ok((out, Some((metadata, id))))
    }

    /// The surface is destroyed: the messages that tell wprsc to unmap its
    /// buffers.
    pub fn destroyed(&self, surface_data: &SurfaceData) -> Vec<Request> {
        let mut out = Vec::new();
        if let Some(cell) = surface_data.data_map.get::<ShmSurfaceCell>()
            && let Some(surf) = cell.0.lock().unwrap().take()
        {
            self.forget(surf, &mut out);
        }
        out
    }
}

/// The surface's last written buffer, compressed for the stream (a new wprsc
/// gets the current contents of all surfaces).
pub fn latest_frame(
    surface_data: &SurfaceData,
    compressor: &mut ShardingCompressor,
) -> Option<CompressedShards> {
    let cell = surface_data.data_map.get::<ShmSurfaceCell>()?;
    let guard = cell.0.lock().unwrap();
    let surf = guard.as_ref()?;
    let slot = &surf.slots[surf.next ^ 1];
    let len = xen_shm::image_len(
        surf.metadata.stride,
        surf.metadata.width,
        surf.metadata.height,
    )?;
    let ptr = slot.buf.as_ptr();
    // SAFETY: the mapping (at least len bytes, allocate) lives as long as the
    // guard, which outlives data.
    let data = unsafe { BufferPointer::new(&ptr, len) };
    Some(filtering::filter_and_compress(data, compressor))
}
