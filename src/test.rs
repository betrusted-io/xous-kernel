// SPDX-FileCopyrightText: 2020 Sean Cross <sean@xobs.io>
// SPDX-License-Identifier: Apache-2.0

use xous::*;
use crate::syscall;

#[test]
fn check_syscall() {
    let call = SysCall::Yield;
    syscall::handle(call);
}

#[test]
fn sanity_check() {
    return;
}
