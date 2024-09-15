#[cfg(target_os="android")]
#[allow(non_snake_case)]
pub mod android {
	extern crate jni;
	use super::*;
	use self::jni::JNIEnv;
	use self::jni::objects::{JClass, JString};
	use self::jni::sys::{jstring};#[no_mangle]
	pub unsafe extern fn Java_com_alterdekim_frida_VPN_greeting(env: JNIEnv, _: JClass, java_name: JString) -> jstring {

		let name: String = env.get_string(java_pattern).expect("invalid pattern string").unwrap().into();
		let mut greeting_string: String = "Hello ".to_owned();

		greeting_string.push_str(&name);env.new_string(greeting_string).unwrap().into_inner()
	}
}