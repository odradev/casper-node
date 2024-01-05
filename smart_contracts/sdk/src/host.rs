#[cfg(not(target_arch = "wasm32"))]
pub mod native;

use std::{
    ffi::c_void,
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ptr::{self, NonNull},
};

#[derive(Debug)]
pub enum Error {
    Foo,
    Bar,
}

macro_rules! dispatch {
    ($name:ident, $($arg:expr),*) => {{
        #[cfg(target_arch = "wasm32"))]
        {
            unsafe { casper_sdk_sys::$name($($arg),*) }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            STUB.with(|stub| {
                
            })::$name($($arg),*)
        }
    }};
}


pub fn casper_print(msg: &str) {
    // let _res = unsafe { casper_sdk_sys::casper_print(msg.as_ptr(), msg.len()) };
    let _res = dispatch!(casper_print, msg.as_ptr(), msg.len());
}

pub fn capser_return(flags: u32, data: &[u8]) -> ! {
    unsafe { casper_sdk_sys::casper_return(flags, data.as_ptr(), data.len()) }
}

pub enum Alloc<F: FnOnce(usize) -> Option<ptr::NonNull<u8>>> {
    Callback(F),
    Static(ptr::NonNull<u8>),
}

pub fn casper_env_read<F: FnOnce(usize) -> Option<ptr::NonNull<u8>>>(
    env_path: &[u64],
    func: F,
) -> Option<NonNull<u8>> {
    let ret = unsafe {
        casper_sdk_sys::casper_env_read(
            env_path.as_ptr(),
            env_path.len(),
            Some(alloc_callback::<F>),
            &func as *const _ as *mut c_void,
        )
    };

    NonNull::<u8>::new(ret)
}

pub fn casper_env_read_into(env_path: &[u64], dest: &mut [u8]) -> Option<NonNull<u8>> {
    let ret = unsafe {
        casper_sdk_sys::casper_env_read(
            env_path.as_ptr(),
            env_path.len(),
            None,
            dest.as_mut_ptr() as *mut c_void,
        )
    };

    NonNull::<u8>::new(ret)
}

extern "C" fn alloc_callback<F: FnOnce(usize) -> Option<ptr::NonNull<u8>>>(
    len: usize,
    ctx: *mut c_void,
) -> *mut u8 {
    let opt_closure = ctx as *mut Option<F>;
    let allocated_ptr = unsafe { (*opt_closure).take().unwrap()(len) };
    match allocated_ptr {
        Some(ptr) => ptr.as_ptr(),
        None => ptr::null_mut(),
    }
}

/// Provided callback should ensure that it can provide a pointer that can store `size` bytes.
/// Function returns last pointer after writing data, or None otherwise.
pub fn copy_input_into<F: FnOnce(usize) -> Option<ptr::NonNull<u8>>>(
    alloc: Option<F>,
) -> Option<NonNull<u8>> {
    let ret = unsafe {
        casper_sdk_sys::casper_copy_input(alloc_callback::<F>, &alloc as *const _ as *mut c_void)
    };
    NonNull::<u8>::new(ret)
}

pub fn casper_copy_input() -> Vec<u8> {
    let mut vec = Vec::new();
    let last_ptr = copy_input_into(Some(|size| reserve_vec_space(&mut vec, size)));
    last_ptr.unwrap();
    vec
}

pub fn copy_input_dest(dest: &mut [u8]) -> Option<&[u8]> {
    let last_ptr = copy_input_into(Some(|size| {
        if size > dest.len() {
            None
        } else {
            // SAFETY: `dest` is guaranteed to be non-null and large enough to hold `size`
            // bytes.
            Some(unsafe { ptr::NonNull::new_unchecked(dest.as_mut_ptr()) })
        }
    }));

    let end_ptr = last_ptr?;
    let length = unsafe { end_ptr.as_ptr().offset_from(dest.as_mut_ptr()) };
    let length: usize = length.try_into().unwrap();
    Some(&dest[..length])
}

pub fn casper_return(flags: ReturnFlags, data: Option<&[u8]>) -> ! {
    let (data_ptr, data_len) = match data {
        Some(data) => (data.as_ptr(), data.len()),
        None => (ptr::null(), 0),
    };
    unsafe { casper_sdk_sys::casper_return(flags.bits(), data_ptr, data_len) };
}

pub fn casper_read<F: FnOnce(usize) -> Option<ptr::NonNull<u8>>>(
    key: Keyspace,
    f: F,
) -> Result<Option<Entry>, Error> {
    let (key_space, key_bytes) = match key {
        Keyspace::State => (0, &[][..]),
        Keyspace::Context(key_bytes) => (1, key_bytes),
    };

    let mut info = casper_sdk_sys::ReadInfo {
        data: ptr::null(),
        size: 0,
        tag: 0,
    };

    extern "C" fn alloc_cb<F: FnOnce(usize) -> Option<ptr::NonNull<u8>>>(
        len: usize,
        ctx: *mut c_void,
    ) -> *mut u8 {
        let opt_closure = ctx as *mut Option<F>;
        let allocated_ptr = unsafe { (*opt_closure).take().unwrap()(len) };
        match allocated_ptr {
            Some(mut ptr) => unsafe { ptr.as_mut() },
            None => ptr::null_mut(),
        }
    }

    let ctx = &Some(f) as *const _ as *mut _;

    let ret = unsafe {
        casper_sdk_sys::casper_read(
            key_space,
            key_bytes.as_ptr(),
            key_bytes.len(),
            &mut info as *mut casper_sdk_sys::ReadInfo,
            alloc_cb::<F>,
            ctx,
        )
    };

    if ret == 0 {
        Ok(Some(Entry { tag: info.tag }))
    } else if ret == 1 {
        Ok(None)
    } else {
        Err(Error::Foo)
    }
}

pub fn casper_write(key: Keyspace, value_tag: u64, value: &[u8]) -> Result<(), Error> {
    let (key_space, key_bytes) = match key {
        Keyspace::State => (0, &[][..]),
        Keyspace::Context(key_bytes) => (1, key_bytes),
    };
    let _ret = unsafe {
        casper_sdk_sys::casper_write(
            key_space,
            key_bytes.as_ptr(),
            key_bytes.len(),
            value_tag,
            value.as_ptr(),
            value.len(),
        )
    };
    Ok(())
}

pub fn casper_create(
    code: Option<&[u8]>,
    manifest: &casper_sdk_sys::Manifest,
    entry_point: Option<&str>,
    input_data: Option<&[u8]>,
) -> Result<casper_sdk_sys::CreateResult, CallError> {
    let (code_ptr, code_size): (*const u8, usize) = match code {
        Some(code) => (code.as_ptr(), code.len()),
        None => (ptr::null(), 0),
    };

    let mut result = MaybeUninit::uninit();

    let manifest_ptr = NonNull::from(manifest);

    let result_code = unsafe {
        casper_sdk_sys::casper_create_contract(
            code_ptr,
            code_size,
            manifest_ptr.as_ptr(),
            entry_point.map(|s| s.as_ptr()).unwrap_or(ptr::null()),
            entry_point.map(|s| s.len()).unwrap_or(0),
            input_data.map(|s| s.as_ptr()).unwrap_or(ptr::null()),
            input_data.map(|s| s.len()).unwrap_or(0),
            result.as_mut_ptr(),
        )
    };

    match ResultCode::from(result_code) {
        ResultCode::Success => {
            let result = unsafe { result.assume_init() };
            Ok(result.into())
        }
        ResultCode::CalleeReverted => Err(CallError::CalleeReverted),
        ResultCode::CalleeTrapped => Err(CallError::CalleeTrapped),
        ResultCode::CalleeGasDepleted => Err(CallError::CalleeGasDepleted),
        ResultCode::Unknown => Err(CallError::Unknown),
    }
}

pub(crate) fn call_into<F: FnOnce(usize) -> Option<ptr::NonNull<u8>>>(
    address: &Address,
    value: u64,
    entry_point: &str,
    input_data: &[u8],
    alloc: Option<F>,
) -> ResultCode {
    let result_code = unsafe {
        casper_sdk_sys::casper_call(
            address.as_ptr(),
            address.len(),
            value,
            entry_point.as_ptr(),
            entry_point.len(),
            input_data.as_ptr(),
            input_data.len(),
            alloc_callback::<F>,
            &alloc as *const _ as *mut _,
        )
    };
    ResultCode::from(result_code)
}

pub fn casper_call(
    address: &Address,
    value: u64,
    entry_point: &str,
    input_data: &[u8],
) -> (Option<Vec<u8>>, ResultCode) {
    let mut output = None;
    let result_code = call_into(
        address,
        value,
        entry_point,
        input_data,
        Some(|size| {
            let mut vec = Vec::new();
            reserve_vec_space(&mut vec, size);
            let result = Some(unsafe { ptr::NonNull::new_unchecked(vec.as_mut_ptr()) });
            output = Some(vec);
            result
        }),
    );
    (output, result_code)
}

use borsh::{BorshDeserialize, BorshSerialize};

use casper_sdk_sys::casper_env_caller;
use vm_common::flags::ReturnFlags;

use crate::{
    reserve_vec_space,
    storage::Keyspace,
    types::{Address, CallError, Entry, ResultCode},
    Contract,
};

pub fn read_vec(key: Keyspace) -> Option<Vec<u8>> {
    let mut vec = Vec::new();
    let out = casper_read(key, |size| reserve_vec_space(&mut vec, size)).unwrap();
    match out {
        Some(_input) => Some(vec),
        None => None,
    }
}

pub fn read_state<T: Default + BorshDeserialize + Contract>() -> Result<T, Error> {
    let mut vec = Vec::new();
    let read_info = casper_read(Keyspace::State, |size| reserve_vec_space(&mut vec, size))?;
    match read_info {
        Some(_input) => Ok(borsh::from_slice(&vec).unwrap()),
        None => Ok(T::default()),
    }
}

pub fn write_state<T: Contract + BorshSerialize>(state: &T) -> Result<(), Error> {
    casper_write(Keyspace::State, 0, &borsh::to_vec(state).unwrap())?;
    Ok(())
}

/// TODO: Remove once procedural macros are improved, this is just to save the boilerplate when
/// doing things manually.
pub fn start<Args: BorshDeserialize, Ret: BorshSerialize>(mut func: impl FnMut(Args) -> Ret) -> ! {
    // Set panic hook (assumes std is enabled etc.)
    #[cfg(target_arch = "wasm32")]
    {
        crate::set_panic_hook();
    }
    let input = casper_copy_input();
    let args: Args = BorshDeserialize::try_from_slice(&input).unwrap();
    let result = func(args);
    let serialized_result = borsh::to_vec(&result).unwrap();
    casper_return(ReturnFlags::empty(), Some(serialized_result.as_slice()));
}

pub fn start_noret<Args: BorshDeserialize, Ret: BorshSerialize>(
    mut func: impl FnMut(Args) -> Ret,
) -> Ret {
    // Set panic hook (assumes std is enabled etc.)
    #[cfg(target_arch = "wasm32")]
    {
        crate::set_panic_hook();
    }
    let input = casper_copy_input();
    let args: Args = BorshDeserialize::try_from_slice(&input).unwrap();
    func(args)
}

pub struct CallResult<T: BorshDeserialize> {
    data: Vec<u8>,
    result: ResultCode,
    marker: PhantomData<T>,
}

pub fn call<Args: BorshSerialize, Ret: BorshDeserialize>(
    contract_address: &Address,
    value: u64,
    entry_point_name: &str,
    args: Args,
) -> Result<CallResult<Ret>, CallError> {
    let input_data = borsh::to_vec(&args).unwrap();
    let (maybe_data, result_code) =
        casper_call(contract_address, value, entry_point_name, &input_data);
    match result_code {
        ResultCode::Success | ResultCode::CalleeReverted => {
            let data = maybe_data.unwrap_or_default();
            Ok(CallResult {
                data,
                result: result_code,
                marker: PhantomData,
            })
        }
        ResultCode::CalleeTrapped => Err(CallError::CalleeTrapped),
        ResultCode::CalleeGasDepleted => Err(CallError::CalleeGasDepleted),
        ResultCode::Unknown => Err(CallError::Unknown),
    }
}

const CASPER_CALLER: u64 = 0;

pub fn get_caller() -> Address {
    let mut addr = MaybeUninit::<Address>::uninit();
    let dest = unsafe { NonNull::new_unchecked(addr.as_mut_ptr() as *mut u8) };

    // Pointer to the end of written bytes
    let _out_ptr = unsafe { casper_env_caller(addr.as_mut_ptr() as *mut _, 32) };

    unsafe { addr.assume_init() }
}

#[cfg(test)]
mod tests {
    use super::start;

    #[test]
    fn foo() {
        start(|arg: String| {})
    }
}
