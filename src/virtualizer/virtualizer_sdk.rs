#[allow(dead_code)]
#[cfg(target_pointer_width = "64")]
#[link(name = "VirtualizerSDK64", kind = "dylib")]
extern "C" {
    #[link_name = "VirtualizerStart"]
    pub fn VIRTUALIZER_START();

    #[link_name = "VirtualizerEnd"]
    pub fn VIRTUALIZER_END();

    #[link_name = "VirtualizerStrEncryptStart"]
    pub fn VIRTUALIZER_STR_ENCRYPT_START();

    #[link_name = "VirtualizerStrEncryptEnd"]
    pub fn VIRTUALIZER_STR_ENCRYPT_END();

    #[link_name = "VirtualizerStrEncryptWStart"]
    pub fn VIRTUALIZER_STR_ENCRYPTW_START();

    #[link_name = "VirtualizerStrEncryptWEnd"]
    pub fn VIRTUALIZER_STR_ENCRYPTW_END();

    #[link_name = "VirtualizerUnprotectedStart"]
    pub fn VIRTUALIZER_UNPROTECTED_START();

    #[link_name = "VirtualizerUnprotectedEnd"]
    pub fn VIRTUALIZER_UNPROTECTED_END();
}

#[allow(dead_code)]
#[cfg(target_pointer_width = "32")]
#[link(name = "VirtualizerSDK32", kind = "dylib")]
extern "C" {
    #[link_name = "VirtualizerStart"]
    pub fn VIRTUALIZER_START();

    #[link_name = "VirtualizerEnd"]
    pub fn VIRTUALIZER_END();

    #[link_name = "VirtualizerStrEncryptStart"]
    pub fn VIRTUALIZER_STR_ENCRYPT_START();

    #[link_name = "VirtualizerStrEncryptEnd"]
    pub fn VIRTUALIZER_STR_ENCRYPT_END();

    #[link_name = "VirtualizerStrEncryptWStart"]
    pub fn VIRTUALIZER_STR_ENCRYPTW_START();

    #[link_name = "VirtualizerStrEncryptWEnd"]
    pub fn VIRTUALIZER_STR_ENCRYPTW_END();

    #[link_name = "VirtualizerUnprotectedStart"]
    pub fn VIRTUALIZER_UNPROTECTED_START();

    #[link_name = "VirtualizerUnprotectedEnd"]
    pub fn VIRTUALIZER_UNPROTECTED_END();
}
