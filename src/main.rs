//! Based on http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html
//! and https://github.com/fdiskyou/injectAllTheThings.

#[cfg(not(windows))]
compile_error!("This crate is currently only compatible with Windows");

use std::{
    env, error,
    ffi::OsString,
    fmt, iter, mem,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::Path,
    ptr, slice,
};

use winapi::{
    ctypes::{c_char, c_void},
    shared::minwindef::FALSE,
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
        minwinbase::LPTHREAD_START_ROUTINE,
        processthreadsapi::{CreateRemoteThread, OpenProcess},
        synchapi::WaitForSingleObject,
        winbase::{
            FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
            FORMAT_MESSAGE_IGNORE_INSERTS, INFINITE, WAIT_FAILED,
        },
        winnt::{
            LANG_NEUTRAL, MAKELANGID, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE, SUBLANG_DEFAULT,
        },
    },
};

fn main() {
    let pid = env::args()
        .nth(1)
        .expect("Expected PID as argument")
        .parse()
        .expect("PID must be a valid positive numer");

    let payload = env::args_os().nth(2).expect("Expected a payload to inject");

    inject_dll(pid, payload.as_ref()).unwrap();
}

// TODO: Handle both 32bit and 64bit victim processes
//
// NOTE: I'm not sure if exposing dll injection as a safe API is a good idea.
fn inject_dll(pid: u32, dll: &Path) -> WinapiResult<()> {
    let process_handle = unsafe {
        let handle = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            FALSE,
            pid,
        );

        if handle != ptr::null_mut() {
            Ok(handle)
        } else {
            Err(WinapiError::last_error())
        }
    }?;

    let payload_file_path: Vec<u16> = dll.as_os_str().encode_wide().chain(iter::once(0)).collect();

    let payload_file_path_target_address = {
        // It might be possible to replace PAGE_EXECUTE_READWRITE with PAGE_READWRITE
        let address = unsafe {
            VirtualAllocEx(
                process_handle,
                ptr::null_mut(),
                payload_file_path.len() * 2,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        if address != ptr::null_mut() {
            Ok(address as *mut _)
        } else {
            Err(WinapiError::last_error())
        }
    }?;

    if unsafe {
        WriteProcessMemory(
            process_handle,
            payload_file_path_target_address,
            payload_file_path.as_ptr() as *const c_void,
            payload_file_path.len() * 2,
            ptr::null_mut(),
        )
    } == 0
    {
        panic!(
            "Could not write payload path to the target process' memory: {}",
            WinapiError::last_error()
        )
    }

    let load_library_w_function_address = {
        let addr = unsafe {
            GetProcAddress(
                GetModuleHandleA("Kernel32\0".as_ptr() as *const c_char),
                "LoadLibraryW\0".as_ptr() as *const c_char,
            )
        };
        if addr == ptr::null_mut() {
            panic!("Could not find LoadLibraryW")
        }

        addr
    };

    let thread = {
        let thread = unsafe {
            CreateRemoteThread(
                process_handle,
                ptr::null_mut(),
                0,
                mem::transmute::<_, LPTHREAD_START_ROUTINE>(load_library_w_function_address),
                payload_file_path_target_address,
                0,
                ptr::null_mut(),
            )
        };
        if thread == ptr::null_mut() {
            panic!(
                "Could not create remote thread: {}",
                WinapiError::last_error()
            );
        }
        thread
    };

    if unsafe { WaitForSingleObject(thread, INFINITE) } == WAIT_FAILED {
        panic!(
            "Could not wait for remote thread to terminate: {}",
            WinapiError::last_error()
        )
    }

    debug_assert_ne!(payload_file_path_target_address, ptr::null_mut());
    unsafe {
        VirtualFreeEx(
            process_handle,
            payload_file_path_target_address,
            0,
            MEM_RELEASE,
        )
    };

    debug_assert_ne!(thread, ptr::null_mut());
    unsafe { CloseHandle(thread) };

    debug_assert_ne!(process_handle, ptr::null_mut());
    unsafe { CloseHandle(process_handle) };

    Ok(())
}

type WinapiResult<T> = Result<T, WinapiError>;
#[derive(Debug)]
struct WinapiError {
    code: u32,
}

impl WinapiError {
    /// Fetches the last error with `GetLastError` and stores it in `Self`
    fn last_error() -> Self {
        let code = unsafe { GetLastError() };

        Self { code }
    }
}

impl fmt::Display for WinapiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message_buffer = ptr::null_mut();

        let len = unsafe {
            FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS,
                ptr::null_mut(),
                self.code,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT) as u32,
                message_buffer,
                0,
                ptr::null_mut(),
            )
        };

        // If the length returned by `FormatMessageW` is 0, then the function failed.
        // It's probably reasonable to panice at that point, since `Display::fmt` isn't
        // a fallible function.
        assert!(len > 0);

        let message_slice = unsafe { slice::from_raw_parts(message_buffer, len as usize) };
        let message = OsString::from_wide(message_slice);

        match message.into_string() {
            Ok(string) => write!(f, "{}", string),
            Err(os_string) => write!(f, "{:?}", os_string),
        }
    }
}

impl error::Error for WinapiError {}
