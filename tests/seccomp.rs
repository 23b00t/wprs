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

// The filter can't be removed again and applies to all threads, so this test
// is its own binary and does not share a process with other tests.
#![cfg(all(feature = "xen", target_arch = "x86_64"))]

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsRawFd;

    use nix::libc;
    use wprs::xen_shm::seccomp;

    // _IOC(_IOC_NONE, 'G', 5, 24): gntalloc's alloc.
    const GRANT_IOCTL: u64 = (24 << 16) | ((b'G' as u64) << 8) | 5;
    // 'T' 0x5401: TCGETS
    const OTHER_IOCTL: u64 = 0x5401;

    const X32_SYSCALL_BIT: libc::c_long = 0x4000_0000;
    const X32_SYS_IOCTL: libc::c_long = 514;

    fn syscall_ioctl(nr: libc::c_long, fd: &File, request: u64) -> (libc::c_long, Option<i32>) {
        // SAFETY: /dev/null rejects these requests without touching the argument.
        let ret = unsafe { libc::syscall(nr, fd.as_raw_fd(), request, 0usize) };
        (ret, std::io::Error::last_os_error().raw_os_error())
    }

    #[test]
    fn filter_blocks_only_grant_ioctls() {
        let null = File::open("/dev/null").unwrap();
        seccomp::forbid_grant_ioctls().unwrap();

        let eperm = (-1, Some(libc::EPERM));
        assert_eq!(syscall_ioctl(libc::SYS_ioctl, &null, GRANT_IOCTL), eperm);
        assert_eq!(
            syscall_ioctl(libc::SYS_ioctl, &null, OTHER_IOCTL),
            (-1, Some(libc::ENOTTY))
        );

        // The x32 ABI reaches ioctl through different syscall numbers.
        for nr in [
            X32_SYSCALL_BIT | libc::SYS_ioctl,
            X32_SYSCALL_BIT | X32_SYS_IOCTL,
        ] {
            assert_eq!(syscall_ioctl(nr, &null, GRANT_IOCTL), eperm, "nr {nr:#x}");
        }
    }
}
