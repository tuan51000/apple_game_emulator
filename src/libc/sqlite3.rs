/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! SQLite3 integration backed by the real SQLite3 amalgamation.
//!
//! Guest code operates with 32-bit opaque pointers to sqlite3 and
//! sqlite3_stmt objects. We allocate small guest memory handles and
//! maintain a mapping from those handles to real host pointers.

use crate::dyld::{export_c_func, FunctionExports};
use crate::fs::GuestPath;
use crate::mem::{ConstPtr, MutPtr, Ptr};
use crate::Environment;
use std::collections::HashMap;
use std::ffi::{CStr, CString};

// Raw FFI to the sqlite3 amalgamation compiled via build.rs
mod ffi {
    use std::os::raw::{c_char, c_int, c_void};

    #[allow(non_camel_case_types)]
    pub type sqlite3 = c_void;
    #[allow(non_camel_case_types)]
    pub type sqlite3_stmt = c_void;

    extern "C" {
        pub fn sqlite3_open(
            filename: *const c_char,
            pp_db: *mut *mut sqlite3,
        ) -> c_int;
        pub fn sqlite3_close(db: *mut sqlite3) -> c_int;
        pub fn sqlite3_prepare_v2(
            db: *mut sqlite3,
            sql: *const c_char,
            n_byte: c_int,
            pp_stmt: *mut *mut sqlite3_stmt,
            pp_tail: *mut *const c_char,
        ) -> c_int;
        pub fn sqlite3_finalize(stmt: *mut sqlite3_stmt) -> c_int;
        pub fn sqlite3_reset(stmt: *mut sqlite3_stmt) -> c_int;
        pub fn sqlite3_step(stmt: *mut sqlite3_stmt) -> c_int;
        pub fn sqlite3_bind_parameter_index(
            stmt: *mut sqlite3_stmt,
            name: *const c_char,
        ) -> c_int;
        pub fn sqlite3_bind_text(
            stmt: *mut sqlite3_stmt,
            index: c_int,
            value: *const c_char,
            n: c_int,
            destructor: isize,
        ) -> c_int;
        pub fn sqlite3_bind_blob(
            stmt: *mut sqlite3_stmt,
            index: c_int,
            value: *const c_void,
            n: c_int,
            destructor: isize,
        ) -> c_int;
        pub fn sqlite3_column_count(
            stmt: *mut sqlite3_stmt,
        ) -> c_int;
        pub fn sqlite3_column_int(
            stmt: *mut sqlite3_stmt,
            col: c_int,
        ) -> c_int;
        pub fn sqlite3_column_text(
            stmt: *mut sqlite3_stmt,
            col: c_int,
        ) -> *const c_char;
        pub fn sqlite3_column_blob(
            stmt: *mut sqlite3_stmt,
            col: c_int,
        ) -> *const c_void;
        pub fn sqlite3_column_bytes(
            stmt: *mut sqlite3_stmt,
            col: c_int,
        ) -> c_int;
        pub fn sqlite3_column_name(
            stmt: *mut sqlite3_stmt,
            col: c_int,
        ) -> *const c_char;
    }

    pub const SQLITE_TRANSIENT: isize = -1;
}

type GuestHandle = MutPtr<()>;

#[derive(Default)]
pub struct State {
    db_handles: HashMap<u32, *mut ffi::sqlite3>,
    stmt_handles: HashMap<u32, *mut ffi::sqlite3_stmt>,
    // Guest memory buffers for returning strings to the guest.
    // Keyed by stmt handle address so we can reuse/free them.
    string_bufs: HashMap<(u32, i32), MutPtr<u8>>,
    blob_bufs: HashMap<(u32, i32), MutPtr<u8>>,
}

fn alloc_handle(env: &mut Environment) -> GuestHandle {
    env.mem.alloc(4).cast()
}

fn sqlite3_open(
    env: &mut Environment,
    path_ptr: ConstPtr<u8>,
    pp_db: MutPtr<GuestHandle>,
) -> i32 {
    let guest_path_str = env.mem.cstr_at_utf8(path_ptr).unwrap().to_owned();
    log!(
        "sqlite3_open({:?})",
        guest_path_str
    );

    let host_path = env
        .fs
        .host_path_for(GuestPath::new(&guest_path_str))
        .unwrap_or_else(|| {
            // Fall back: place the DB in the sandbox directory
            let sandbox = crate::paths::user_data_base_path();
            sandbox.join(
                std::path::Path::new(&guest_path_str)
                    .file_name()
                    .unwrap_or(std::ffi::OsStr::new("game.db")),
            )
        });

    let host_path_c =
        CString::new(host_path.to_str().unwrap()).unwrap();

    let mut raw_db: *mut ffi::sqlite3 = std::ptr::null_mut();
    let rc = unsafe { ffi::sqlite3_open(host_path_c.as_ptr(), &mut raw_db) };

    if rc == 0 && !raw_db.is_null() {
        let handle = alloc_handle(env);
        let key = handle.to_bits();
        env.libc_state.sqlite3.db_handles.insert(key, raw_db);
        env.mem.write(pp_db, handle);
        log!(
            "sqlite3_open: opened {:?} as handle {:?}",
            host_path,
            handle
        );
    } else {
        env.mem.write(pp_db, Ptr::null());
        log!("sqlite3_open: failed with rc={}", rc);
    }
    rc
}

fn sqlite3_close(env: &mut Environment, db: GuestHandle) -> i32 {
    let key = db.to_bits();
    if let Some(raw_db) = env.libc_state.sqlite3.db_handles.remove(&key) {
        let rc = unsafe { ffi::sqlite3_close(raw_db) };
        log!("sqlite3_close({:?}) => {}", db, rc);
        rc
    } else {
        log!("sqlite3_close({:?}): unknown handle", db);
        0
    }
}

fn sqlite3_prepare_v2(
    env: &mut Environment,
    db: GuestHandle,
    sql_ptr: ConstPtr<u8>,
    n_byte: i32,
    pp_stmt: MutPtr<MutPtr<()>>,
    _pp_tail: MutPtr<ConstPtr<u8>>,
) -> i32 {
    let db_key = db.to_bits();
    let raw_db = match env.libc_state.sqlite3.db_handles.get(&db_key) {
        Some(&ptr) => ptr,
        None => {
            log!("sqlite3_prepare_v2: unknown db handle {:?}", db);
            env.mem.write(pp_stmt, Ptr::null());
            return 1; // SQLITE_ERROR
        }
    };

    let sql = if n_byte < 0 {
        let s = env.mem.cstr_at_utf8(sql_ptr).unwrap();
        CString::new(s).unwrap()
    } else {
        let bytes = env.mem.bytes_at(sql_ptr, n_byte as u32);
        CString::new(bytes).unwrap_or_else(|_| CString::new("").unwrap())
    };

    let mut raw_stmt: *mut ffi::sqlite3_stmt = std::ptr::null_mut();
    let rc = unsafe {
        ffi::sqlite3_prepare_v2(
            raw_db,
            sql.as_ptr(),
            -1,
            &mut raw_stmt,
            std::ptr::null_mut(),
        )
    };

    if rc == 0 && !raw_stmt.is_null() {
        let handle = alloc_handle(env);
        let key = handle.to_bits();
        env.libc_state.sqlite3.stmt_handles.insert(key, raw_stmt);
        env.mem.write(pp_stmt, handle);
    } else {
        env.mem.write(pp_stmt, Ptr::null());
    }
    rc
}

fn sqlite3_finalize(env: &mut Environment, stmt: MutPtr<()>) -> i32 {
    let key = stmt.to_bits();
    if let Some(raw_stmt) = env.libc_state.sqlite3.stmt_handles.remove(&key) {
        let rc = unsafe { ffi::sqlite3_finalize(raw_stmt) };
        rc
    } else {
        0
    }
}

fn sqlite3_reset(env: &mut Environment, stmt: MutPtr<()>) -> i32 {
    let key = stmt.to_bits();
    match env.libc_state.sqlite3.stmt_handles.get(&key) {
        Some(&raw_stmt) => unsafe { ffi::sqlite3_reset(raw_stmt) },
        None => 0,
    }
}

fn sqlite3_step(env: &mut Environment, stmt: MutPtr<()>) -> i32 {
    let key = stmt.to_bits();
    match env.libc_state.sqlite3.stmt_handles.get(&key) {
        Some(&raw_stmt) => unsafe { ffi::sqlite3_step(raw_stmt) },
        None => 101, // SQLITE_DONE
    }
}

fn sqlite3_bind_parameter_index(
    env: &mut Environment,
    stmt: MutPtr<()>,
    name: ConstPtr<u8>,
) -> i32 {
    let key = stmt.to_bits();
    let raw_stmt = match env.libc_state.sqlite3.stmt_handles.get(&key) {
        Some(&ptr) => ptr,
        None => return 0,
    };
    let name_str = env.mem.cstr_at_utf8(name).unwrap();
    let name_c = CString::new(name_str).unwrap();
    unsafe { ffi::sqlite3_bind_parameter_index(raw_stmt, name_c.as_ptr()) }
}

fn sqlite3_bind_text(
    env: &mut Environment,
    stmt: MutPtr<()>,
    index: i32,
    value: ConstPtr<u8>,
    n: i32,
    _destructor: MutPtr<()>,
) -> i32 {
    let key = stmt.to_bits();
    let raw_stmt = match env.libc_state.sqlite3.stmt_handles.get(&key) {
        Some(&ptr) => ptr,
        None => return 0,
    };

    if value.is_null() {
        return unsafe {
            ffi::sqlite3_bind_text(
                raw_stmt,
                index,
                std::ptr::null(),
                0,
                ffi::SQLITE_TRANSIENT,
            )
        };
    }

    let text = if n < 0 {
        let s = env.mem.cstr_at_utf8(value).unwrap();
        s.as_bytes().to_vec()
    } else {
        env.mem.bytes_at(value, n as u32).to_vec()
    };
    let c_text = CString::new(text).unwrap_or_else(|_| CString::new("").unwrap());

    unsafe {
        ffi::sqlite3_bind_text(
            raw_stmt,
            index,
            c_text.as_ptr(),
            -1,
            ffi::SQLITE_TRANSIENT,
        )
    }
}

fn sqlite3_bind_blob(
    env: &mut Environment,
    stmt: MutPtr<()>,
    index: i32,
    value: ConstPtr<()>,
    n: i32,
    _destructor: MutPtr<()>,
) -> i32 {
    let key = stmt.to_bits();
    let raw_stmt = match env.libc_state.sqlite3.stmt_handles.get(&key) {
        Some(&ptr) => ptr,
        None => return 0,
    };

    if value.is_null() || n <= 0 {
        return unsafe {
            ffi::sqlite3_bind_blob(
                raw_stmt,
                index,
                std::ptr::null(),
                0,
                ffi::SQLITE_TRANSIENT,
            )
        };
    }

    let blob = env.mem.bytes_at(value.cast::<u8>(), n as u32).to_vec();

    unsafe {
        ffi::sqlite3_bind_blob(
            raw_stmt,
            index,
            blob.as_ptr() as *const _,
            n,
            ffi::SQLITE_TRANSIENT,
        )
    }
}

fn sqlite3_column_count(env: &mut Environment, stmt: MutPtr<()>) -> i32 {
    let key = stmt.to_bits();
    match env.libc_state.sqlite3.stmt_handles.get(&key) {
        Some(&raw_stmt) => unsafe { ffi::sqlite3_column_count(raw_stmt) },
        None => 0,
    }
}

fn sqlite3_column_int(
    env: &mut Environment,
    stmt: MutPtr<()>,
    col: i32,
) -> i32 {
    let key = stmt.to_bits();
    match env.libc_state.sqlite3.stmt_handles.get(&key) {
        Some(&raw_stmt) => unsafe { ffi::sqlite3_column_int(raw_stmt, col) },
        None => 0,
    }
}

fn sqlite3_column_text(
    env: &mut Environment,
    stmt: MutPtr<()>,
    col: i32,
) -> ConstPtr<u8> {
    let key = stmt.to_bits();
    let raw_stmt = match env.libc_state.sqlite3.stmt_handles.get(&key) {
        Some(&ptr) => ptr,
        None => return Ptr::null(),
    };

    let text_ptr = unsafe { ffi::sqlite3_column_text(raw_stmt, col) };
    if text_ptr.is_null() {
        return Ptr::null();
    }

    let c_str = unsafe { CStr::from_ptr(text_ptr) };
    let bytes = c_str.to_bytes_with_nul();

    let buf_key = (key, col);
    let guest_buf = env.mem.alloc(bytes.len().try_into().unwrap());
    env.mem
        .bytes_at_mut(guest_buf.cast::<u8>(), bytes.len().try_into().unwrap())
        .copy_from_slice(bytes);
    env.libc_state
        .sqlite3
        .string_bufs
        .insert(buf_key, guest_buf.cast());

    guest_buf.cast_const().cast()
}

fn sqlite3_column_blob(
    env: &mut Environment,
    stmt: MutPtr<()>,
    col: i32,
) -> ConstPtr<()> {
    let key = stmt.to_bits();
    let raw_stmt = match env.libc_state.sqlite3.stmt_handles.get(&key) {
        Some(&ptr) => ptr,
        None => return Ptr::null(),
    };

    let blob_ptr = unsafe { ffi::sqlite3_column_blob(raw_stmt, col) };
    let blob_len = unsafe { ffi::sqlite3_column_bytes(raw_stmt, col) };
    if blob_ptr.is_null() || blob_len <= 0 {
        return Ptr::null();
    }

    let blob =
        unsafe { std::slice::from_raw_parts(blob_ptr as *const u8, blob_len as usize) };
    let guest_buf = env.mem.alloc(blob_len as u32);
    env.mem
        .bytes_at_mut(guest_buf.cast::<u8>(), blob_len as u32)
        .copy_from_slice(blob);
    env.libc_state
        .sqlite3
        .blob_bufs
        .insert((key, col), guest_buf.cast());

    guest_buf.cast_const().cast()
}

fn sqlite3_column_bytes(
    env: &mut Environment,
    stmt: MutPtr<()>,
    col: i32,
) -> i32 {
    let key = stmt.to_bits();
    match env.libc_state.sqlite3.stmt_handles.get(&key) {
        Some(&raw_stmt) => unsafe { ffi::sqlite3_column_bytes(raw_stmt, col) },
        None => 0,
    }
}

fn sqlite3_column_name(
    env: &mut Environment,
    stmt: MutPtr<()>,
    col: i32,
) -> ConstPtr<u8> {
    let key = stmt.to_bits();
    let raw_stmt = match env.libc_state.sqlite3.stmt_handles.get(&key) {
        Some(&ptr) => ptr,
        None => return Ptr::null(),
    };

    let name_ptr = unsafe { ffi::sqlite3_column_name(raw_stmt, col) };
    if name_ptr.is_null() {
        return Ptr::null();
    }

    let c_str = unsafe { CStr::from_ptr(name_ptr) };
    let bytes = c_str.to_bytes_with_nul();

    let guest_buf = env.mem.alloc(bytes.len().try_into().unwrap());
    env.mem
        .bytes_at_mut(guest_buf.cast::<u8>(), bytes.len().try_into().unwrap())
        .copy_from_slice(bytes);

    guest_buf.cast_const().cast()
}

pub const FUNCTIONS: FunctionExports = &[
    export_c_func!(sqlite3_open(_, _)),
    export_c_func!(sqlite3_close(_)),
    export_c_func!(sqlite3_prepare_v2(_, _, _, _, _)),
    export_c_func!(sqlite3_finalize(_)),
    export_c_func!(sqlite3_reset(_)),
    export_c_func!(sqlite3_step(_)),
    export_c_func!(sqlite3_bind_parameter_index(_, _)),
    export_c_func!(sqlite3_bind_text(_, _, _, _, _)),
    export_c_func!(sqlite3_bind_blob(_, _, _, _, _)),
    export_c_func!(sqlite3_column_count(_)),
    export_c_func!(sqlite3_column_int(_, _)),
    export_c_func!(sqlite3_column_text(_, _)),
    export_c_func!(sqlite3_column_blob(_, _)),
    export_c_func!(sqlite3_column_bytes(_, _)),
    export_c_func!(sqlite3_column_name(_, _)),
];

pub const DYLIB: crate::dyld::HostDylib = crate::dyld::HostDylib {
    path: "/usr/lib/libsqlite3.dylib",
    aliases: &[],
    class_exports: &[],
    constant_exports: &[],
    function_exports: &[FUNCTIONS],
};
