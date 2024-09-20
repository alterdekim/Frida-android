mod client;
mod config;
mod udp;

use std::os::raw::{c_char};
use std::ffi::{CString, CStr};

#[no_mangle]
pub extern fn rust_greeting(to: *const c_char) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(to) };
    let recipient = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    CString::new("Hello ".to_owned() + recipient).unwrap().into_raw()
}


/// Expose the JNI interface for android below
#[cfg(target_os="android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use config::ClientConfiguration;
    use fast32::base32::RFC4648;

    use super::*;
    use self::jni::JNIEnv;
    use self::jni::objects::{JClass, JString};
    use self::jni::sys::{jstring};

    #[no_mangle]
    pub unsafe extern fn Java_com_alterdekim_frida_FridaVPN_startClient(env: JNIEnv, _: JClass, java_pattern: JString) {
        // Our Java companion code might pass-in "world" as a string, hence the name.
        //let world = rust_greeting(env.get_string(java_pattern).expect("invalid pattern string").as_ptr());
        // Retake pointer so that we can use it below and allow memory to be freed when it goes out of scope.
        //let world_ptr = CString::from_raw(world);
        //let output = env.new_string(world_ptr.to_str().unwrap()).expect("Couldn't create java string!");

        //output.into_inner()

        let wo = env.get_string(java_pattern).expect("invalid pattern string").as_ptr();
        let c_str = unsafe { CStr::from_ptr(wo) };
        let cfg_raw = match c_str.to_str() {
            Err(_) => "",
            Ok(string) => string,
        };

        let config: ClientConfiguration = serde_yaml::from_slice(RFC4648.decode(cfg_raw.as_bytes()).unwrap().as_slice()).expect("Bad client config file structure");
        //client::client_mode(config);

        //let output = env.new_string("gabber").expect("Couldn't create java string!");
        
        //output.into_inner()
    }
}
