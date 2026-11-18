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

//! A seccomp filter for processes that use the fds of the grant broker: the
//! grant ioctls (type 'G', gntalloc, gntdev) fail with EPERM, so the fds can
//! only be mapped. Whoever can issue those ioctls can share pages with, or map
//! grants of, any domain.

use std::collections::BTreeMap;
use std::path::PathBuf;

use nix::libc;
use seccompiler::BpfProgram;
use seccompiler::SeccompAction;
use seccompiler::SeccompCmpArgLen;
use seccompiler::SeccompCmpOp;
use seccompiler::SeccompCondition;
use seccompiler::SeccompFilter;
use seccompiler::SeccompRule;

use crate::prelude::*;

/// `_IOC_TYPE` of the grant devices' ioctls.
const GRANT_IOCTL_TYPE: u8 = b'G';

// Syscall numbers of ioctl on the x32 ABI (a syscall number with this bit set
// is dispatched to the x32 table on x86_64 and is not covered by SYS_ioctl).
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: i64 = 0x4000_0000;
#[cfg(target_arch = "x86_64")]
const X32_SYS_IOCTL: i64 = 514;

fn ioctl_numbers() -> Vec<i64> {
    let ioctl = libc::SYS_ioctl;
    #[cfg(target_arch = "x86_64")]
    return vec![
        ioctl,
        ioctl | X32_SYSCALL_BIT,
        X32_SYS_IOCTL | X32_SYSCALL_BIT,
    ];
    #[cfg(not(target_arch = "x86_64"))]
    vec![ioctl]
}

fn filter() -> Result<BpfProgram> {
    // The request is the second argument; its type is in bits 8..16.
    let rule = SeccompRule::new(vec![
        SeccompCondition::new(
            1,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(0xff00),
            u64::from(GRANT_IOCTL_TYPE) << 8,
        )
        .location(loc!())?,
    ])
    .location(loc!())?;
    let rules = ioctl_numbers()
        .into_iter()
        .map(|nr| (nr, vec![rule.clone()]))
        .collect::<BTreeMap<_, _>>();
    // The compiled program kills the process on any other architecture
    // (e.g. i386 through int 0x80).
    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(u32::try_from(libc::EPERM).location(loc!())?),
        std::env::consts::ARCH.try_into().location(loc!())?,
    )
    .location(loc!())?
    .try_into()
    .location(loc!())
}

/// Installs the filter on all threads of the process; it can't be removed.
/// Call it once, before connecting to the broker.
#[instrument(skip_all, level = "debug")]
pub fn forbid_grant_ioctls() -> Result<()> {
    seccompiler::apply_filter_all_threads(&filter().location(loc!())?).location(loc!())
}

/// For the binaries, at startup before any broker fd exists: installs the
/// filter if a broker socket is configured. Returns the socket to use, None
/// (pixels over the stream) if there is none or the filter couldn't be
/// installed.
pub fn restrict_if_configured(socket: Option<PathBuf>) -> Option<PathBuf> {
    socket.filter(|_| {
        forbid_grant_ioctls()
            .context(
                loc!(),
                "can't restrict grant ioctls, pixels come over the stream",
            )
            .warn(loc!())
            .is_ok()
    })
}
