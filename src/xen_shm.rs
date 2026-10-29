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

//! Pixel buffers in Xen grant-shared memory: wprsd (in a domU) writes into
//! pages granted read-only to dom0, wprsc (in dom0) maps them. Neither opens
//! the Xen grant devices: a broker (nox-relay's `grants` socket, root) hands
//! them the fd of exactly those pages, and seccomp forbids the grant ioctls
//! on it (whoever can do them can share pages with, or map grants of, any
//! domain). Closing the fd frees the grants or mappings.
//!
//! Broker protocol on a stream socket, `u32 LE length` + body each way:
//! - `A` + u32 pages → `O` + u64 mmap offset + u32 refs[pages], fd (guest)
//! - `M` + u32 refs[n] → `O` + u64 mmap offset, fd (dom0)
//! - failure: `E` + message, no fd
//!
//! Without the `xen` feature nothing connects and wprs keeps sending pixels
//! over the stream.

use std::os::fd::OwnedFd;
use std::ptr::NonNull;

use crate::serialization::geometry::Rectangle;

pub const PAGE_SIZE: usize = 4096;

/// Pages of `len` bytes, granted to dom0 and mapped here read-write.
#[derive(Debug)]
pub struct SharedBuffer {
    ptr: NonNull<u8>,
    len: usize,
    pub refs: Vec<u32>,
    #[allow(dead_code)]
    fd: OwnedFd,
}

// SAFETY: the mapping is owned by this struct and only accessed through it.
unsafe impl Send for SharedBuffer {}
// SAFETY: see above; writes need &mut self.
unsafe impl Sync for SharedBuffer {}

impl SharedBuffer {
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Granted pages of another domain, mapped here read-only.
#[derive(Debug)]
pub struct MappedBuffer {
    ptr: NonNull<u8>,
    len: usize,
    #[allow(dead_code)]
    fd: OwnedFd,
}

// SAFETY: the mapping is owned by this struct and only read through it.
unsafe impl Send for MappedBuffer {}
// SAFETY: see above.
unsafe impl Sync for MappedBuffer {}

impl MappedBuffer {
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(feature = "xen")]
mod imp {
    use std::io::IoSliceMut;
    use std::io::Read;
    use std::io::Write;
    use std::num::NonZeroUsize;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::ptr::NonNull;
    use std::sync::Mutex;
    use std::sync::Once;

    use nix::libc;
    use nix::sys::mman;
    use nix::sys::mman::MapFlags;
    use nix::sys::mman::ProtFlags;
    use nix::sys::socket;
    use nix::sys::socket::ControlMessageOwned;
    use nix::sys::socket::MsgFlags;

    use super::MappedBuffer;
    use super::PAGE_SIZE;
    use super::SharedBuffer;
    use crate::prelude::*;

    // Requests the broker answers at most (nox-relay's grants.rs MAX_PAGES).
    const MAX_PAGES: usize = 16384;

    #[derive(Debug)]
    struct Broker(Mutex<UnixStream>);

    impl Broker {
        fn connect(path: &Path) -> Result<Self> {
            forbid_grant_ioctls().location(loc!())?;
            let conn = UnixStream::connect(path)
                .map_err(|e| anyhow!("connecting to {}: {e}", path.display()))?;
            Ok(Self(Mutex::new(conn)))
        }

        /// Sends a request, returns the reply body and its fd.
        fn call(&self, req: &[u8]) -> Result<(Vec<u8>, OwnedFd)> {
            let mut conn = self.0.lock().unwrap();
            let mut msg = (req.len() as u32).to_le_bytes().to_vec();
            msg.extend_from_slice(req);
            conn.write_all(&msg).location(loc!())?;

            // The fd comes with the first byte of the reply.
            let mut len = [0u8; 4];
            let mut fd = None;
            let got = {
                let mut iov = [IoSliceMut::new(&mut len)];
                let mut cmsg = nix::cmsg_space!(libc::c_int);
                let msg = socket::recvmsg::<()>(
                    conn.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg),
                    MsgFlags::MSG_CMSG_CLOEXEC,
                )
                .location(loc!())?;
                for c in msg.cmsgs().location(loc!())? {
                    if let ControlMessageOwned::ScmRights(fds) = c {
                        for raw in fds {
                            // SAFETY: a fresh fd received with SCM_RIGHTS, ours now.
                            let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                            fd.get_or_insert(owned);
                        }
                    }
                }
                msg.bytes
            };
            if got == 0 {
                bail!("the grant broker closed the connection");
            }
            conn.read_exact(&mut len[got..]).location(loc!())?;
            let len = u32::from_le_bytes(len) as usize;
            if len > 9 + 4 * MAX_PAGES {
                bail!("grant broker reply too large");
            }
            let mut body = vec![0u8; len];
            conn.read_exact(&mut body).location(loc!())?;
            match (body.first(), fd) {
                (Some(b'O'), Some(fd)) => Ok((body, fd)),
                (Some(b'E'), _) => bail!("grant broker: {}", String::from_utf8_lossy(&body[1..])),
                _ => bail!("grant broker: unexpected reply"),
            }
        }
    }

    fn offset(body: &[u8]) -> Result<u64> {
        Ok(u64::from_le_bytes(
            body.get(1..9)
                .location(loc!())?
                .try_into()
                .location(loc!())?,
        ))
    }

    fn mmap(fd: &OwnedFd, len: usize, prot: ProtFlags, offset: u64) -> Result<NonNull<u8>> {
        // SAFETY: a fresh shared mapping of the device, not aliasing anything.
        let ptr = unsafe {
            mman::mmap(
                None,
                NonZeroUsize::new(len).location(loc!())?,
                prot,
                MapFlags::MAP_SHARED,
                fd,
                offset as libc::off_t,
            )
        }
        .location(loc!())?;
        Ok(ptr.cast())
    }

    /// wprsd: shares pages with dom0 through the guest's broker.
    #[derive(Debug)]
    pub struct GrantAlloc(Broker);

    impl GrantAlloc {
        pub fn connect(path: &Path) -> Result<Self> {
            Ok(Self(Broker::connect(path)?))
        }

        /// `len` bytes (rounded up to pages), granted read-only to dom0.
        pub fn share(&self, len: usize) -> Result<SharedBuffer> {
            let pages = len.div_ceil(PAGE_SIZE);
            let mut req = b"A".to_vec();
            req.extend_from_slice(&(pages as u32).to_le_bytes());
            let (body, fd) = self.0.call(&req)?;
            if body.len() != 9 + 4 * pages {
                bail!("grant broker: {} bytes for {pages} pages", body.len());
            }
            let refs = body[9..]
                .chunks_exact(4)
                .map(|r| u32::from_le_bytes(r.try_into().unwrap()))
                .collect();
            let len = pages * PAGE_SIZE;
            let ptr = mmap(
                &fd,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                offset(&body)?,
            )?;
            Ok(SharedBuffer { ptr, len, refs, fd })
        }
    }

    impl Drop for SharedBuffer {
        fn drop(&mut self) {
            // SAFETY: we own the mapping. Closing the fd (after this) frees
            // the grants once dom0 has unmapped them too.
            unsafe { mman::munmap(self.ptr.cast(), self.len) }.log_and_ignore(loc!());
        }
    }

    /// wprsc: maps a VM's grants through dom0's broker for that VM.
    #[derive(Debug)]
    pub struct GrantMap(Broker);

    impl GrantMap {
        pub fn connect(path: &Path) -> Result<Self> {
            Ok(Self(Broker::connect(path)?))
        }

        /// Maps the pages `refs` the VM granted, read-only.
        pub fn map(&self, refs: &[u32]) -> Result<MappedBuffer> {
            let mut req = b"M".to_vec();
            for r in refs {
                req.extend_from_slice(&r.to_le_bytes());
            }
            let (body, fd) = self.0.call(&req)?;
            let len = refs.len() * PAGE_SIZE;
            let ptr = mmap(&fd, len, ProtFlags::PROT_READ, offset(&body)?)?;
            Ok(MappedBuffer { ptr, len, fd })
        }
    }

    impl Drop for MappedBuffer {
        fn drop(&mut self) {
            // SAFETY: we own the mapping; closing the fd unmaps the grants.
            unsafe { mman::munmap(self.ptr.cast(), self.len) }.log_and_ignore(loc!());
        }
    }

    /// seccomp for the whole process: ioctls of type 'G' (gntalloc, gntdev,
    /// …) fail with EPERM, so the fds from the broker can only be mapped.
    #[cfg(target_arch = "x86_64")]
    fn forbid_grant_ioctls() -> Result<()> {
        static ONCE: Once = Once::new();
        let mut result = Ok(());
        ONCE.call_once(|| result = install_filter());
        result
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn forbid_grant_ioctls() -> Result<()> {
        bail!("grant ioctl filter only for x86_64")
    }

    #[cfg(target_arch = "x86_64")]
    fn install_filter() -> Result<()> {
        // linux/bpf_common.h, linux/seccomp.h, linux/audit.h
        const LD_W_ABS: u16 = 0x00 | 0x00 | 0x20;
        const JMP_JEQ_K: u16 = 0x05 | 0x10 | 0x00;
        const ALU_AND_K: u16 = 0x04 | 0x50 | 0x00;
        const RET_K: u16 = 0x06;
        const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
        const RET_ALLOW: u32 = 0x7fff_0000;
        const RET_ERRNO: u32 = 0x0005_0000;
        // struct seccomp_data: nr, arch, ip, args[6] (low half of args[1] at 24)
        let stmt = |code, k| libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        };
        let jump = |k, jt, jf| libc::sock_filter {
            code: JMP_JEQ_K,
            jt,
            jf,
            k,
        };
        let filter = [
            stmt(LD_W_ABS, 4),
            jump(AUDIT_ARCH_X86_64, 0, 5),
            stmt(LD_W_ABS, 0),
            jump(libc::SYS_ioctl as u32, 0, 3),
            stmt(LD_W_ABS, 24),
            stmt(ALU_AND_K, 0xff00),
            jump(u32::from(b'G') << 8, 1, 0),
            stmt(RET_K, RET_ALLOW),
            stmt(RET_K, RET_ERRNO | libc::EPERM as u32),
        ];
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr().cast_mut(),
        };
        // SAFETY: plain prctl/seccomp calls with a valid filter program.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                bail!("PR_SET_NO_NEW_PRIVS: {}", std::io::Error::last_os_error());
            }
            // TSYNC: all threads, also the ones started before
            if libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_TSYNC,
                &prog as *const libc::sock_fprog,
            ) != 0
            {
                bail!("seccomp: {}", std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn filter_blocks_only_grant_ioctls() {
        use std::fs::File;
        let null = File::open("/dev/null").unwrap();
        let ioctl = |req: u64| {
            // SAFETY: /dev/null rejects both requests without touching arg.
            let ret = unsafe { libc::ioctl(null.as_raw_fd(), req as _, 0usize) };
            (ret, std::io::Error::last_os_error().raw_os_error())
        };
        // _IOC(_IOC_NONE, 'G', 5, 24): gntalloc's alloc; 'T' 0x5401: TCGETS
        let grant = (24 << 16) | (u64::from(b'G') << 8) | 5;
        forbid_grant_ioctls().unwrap();
        assert_eq!(ioctl(grant), (-1, Some(libc::EPERM)));
        assert_eq!(ioctl(0x5401), (-1, Some(libc::ENOTTY)));
    }
}

#[cfg(not(feature = "xen"))]

mod imp {
    use std::path::Path;

    use super::MappedBuffer;
    use super::SharedBuffer;
    use crate::prelude::*;

    #[derive(Debug)]
    pub struct GrantAlloc;

    impl GrantAlloc {
        pub fn connect(_path: &Path) -> Result<Self> {
            bail!("built without the xen feature")
        }

        pub fn share(&self, _len: usize) -> Result<SharedBuffer> {
            unreachable!()
        }
    }

    #[derive(Debug)]
    pub struct GrantMap;

    impl GrantMap {
        pub fn connect(_path: &Path) -> Result<Self> {
            bail!("built without the xen feature")
        }

        pub fn map(&self, _refs: &[u32]) -> Result<MappedBuffer> {
            unreachable!()
        }
    }
}

pub use imp::GrantAlloc;
pub use imp::GrantMap;

/// Bytes of a `width` x `height` image with 4 bytes per pixel and `stride`,
/// None if that doesn't make sense or overflows (the values come from the
/// other side and decide how much copy_rects touches).
pub fn image_len(stride: i32, width: i32, height: i32) -> Option<usize> {
    let row = usize::try_from(width).ok()?.checked_mul(4)?;
    let stride = usize::try_from(stride).ok()?;
    if row == 0 || height <= 0 || stride < row {
        return None;
    }
    stride.checked_mul(usize::try_from(height).ok()?)
}

/// Copies the rectangles `rects` (None: everything) of a `width` x `height`
/// image with 4 bytes per pixel and `stride` from `src` to `dst`.
///
/// # Safety
///
/// `src` and `dst` must be valid for `image_len(stride, width, height)` bytes
/// (Some) and not overlap.
pub unsafe fn copy_rects(
    src: *const u8,
    dst: *mut u8,
    stride: usize,
    width: i32,
    height: i32,
    rects: Option<&[Rectangle<i32>]>,
) {
    let Some(rects) = rects else {
        // SAFETY: by the caller.
        unsafe { std::ptr::copy_nonoverlapping(src, dst, stride * height as usize) };
        return;
    };
    for rect in rects {
        let x0 = rect.loc.x.clamp(0, width);
        let y0 = rect.loc.y.clamp(0, height);
        let x1 = rect.loc.x.saturating_add(rect.size.w).clamp(0, width);
        let y1 = rect.loc.y.saturating_add(rect.size.h).clamp(0, height);
        if x1 <= x0 || y1 <= y0 {
            continue;
        }
        let (x0, x1) = (x0 as usize * 4, x1 as usize * 4);
        for y in y0 as usize..y1 as usize {
            let off = y * stride + x0;
            // SAFETY: off + (x1 - x0) <= y * stride + width * 4 <= stride * height.
            unsafe { std::ptr::copy_nonoverlapping(src.add(off), dst.add(off), x1 - x0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_rects_copies_only_damage() {
        let (width, height, stride) = (4, 3, 20);
        let src: Vec<u8> = (0..stride * height).map(|i| i as u8).collect();
        let mut dst = vec![0u8; stride * height];
        let rects = [
            Rectangle::new(1, 1, 2, 1),
            // Clipped to the image
            Rectangle::new(3, 2, 5, 5),
        ];
        // SAFETY: both are stride * height bytes.
        unsafe {
            copy_rects(
                src.as_ptr(),
                dst.as_mut_ptr(),
                stride,
                width as i32,
                height as i32,
                Some(&rects),
            )
        };
        for (i, (s, d)) in src.iter().zip(&dst).enumerate() {
            let (x, y) = ((i % stride) / 4, i / stride);
            let damaged = (y == 1 && (1..3).contains(&x)) || (y == 2 && x == 3);
            assert_eq!(*d, if damaged { *s } else { 0 }, "byte {i}");
        }

        // SAFETY: as above.
        unsafe {
            copy_rects(
                src.as_ptr(),
                dst.as_mut_ptr(),
                stride,
                width as i32,
                height as i32,
                None,
            )
        };
        assert_eq!(src, dst);
    }

    #[test]
    fn image_len_rejects_nonsense() {
        assert_eq!(image_len(20, 4, 3), Some(60));
        assert_eq!(image_len(8, 4, 3), None); // stride < width * 4
        assert_eq!(image_len(16, 0, 3), None);
        assert_eq!(image_len(16, 4, -1), None);
        assert_eq!(image_len(-16, 4, 3), None);
        // i32 overflow of stride * height must not wrap to something small
        assert_eq!(
            image_len(i32::MAX, 4, i32::MAX),
            (i32::MAX as usize).checked_mul(i32::MAX as usize)
        );
    }
}
