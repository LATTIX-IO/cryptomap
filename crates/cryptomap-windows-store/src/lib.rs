//! Windows read-only public X.509 store provider for the safe cryptomap SDK.
//!
//! The companion crate isolates Win32 FFI and never links native APIs into
//! cryptomap core. Only explicit store targets from the trusted host may be
//! opened; no calls inspect/export private keys, run network verification,
//! enumerate unrelated stores or modify user/machine certificate stores.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

use cryptomap::{
    certificate_store_scope::CertificateStoreTarget,
    collectors::certificate_store::{PublicCertificateStoreBackend, StoreProviderError},
};

/// Platform provider that reads only public certificate DER from an exact
/// host-granted CurrentUser/My or LocalMachine/My Windows registry store.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsCertificateStoreBackend;

#[cfg(not(windows))]
impl PublicCertificateStoreBackend for WindowsCertificateStoreBackend {
    fn visit(
        &self,
        _target: CertificateStoreTarget,
        _visitor: &mut dyn FnMut(&[u8]) -> Result<(), StoreProviderError>,
    ) -> Result<(), StoreProviderError> {
        Err(StoreProviderError::Unsupported)
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use cryptomap::{
        certificate_store_scope::{CertificateStoreLocation, CertificateStoreName},
        collectors::certificate::MAX_CERT_DER_BYTES,
    };
    use std::{ffi::c_void, ptr, slice};
    use windows_sys::Win32::{
        Foundation::GetLastError,
        Security::Cryptography::{
            CERT_CONTEXT, CERT_STORE_OPEN_EXISTING_FLAG,
            CERT_STORE_PROV_SYSTEM_REGISTRY_W, CERT_STORE_READONLY_FLAG,
            CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE, CertCloseStore,
            CertEnumCertificatesInStore, CertFreeCertificateContext, CertOpenStore, HCERTSTORE,
        },
    };

    #[cfg(test)]
    use windows_sys::Win32::Security::Cryptography::CERT_STORE_PROV_MEMORY;

    const CRYPT_E_NOT_FOUND: u32 = 0x8009_2004;
    const ERROR_NO_MORE_FILES: u32 = 18;

    /// RAII-owned store, never transferable to a caller or to a private-key API.
    struct OwnedStore(HCERTSTORE);
    impl OwnedStore {
        fn open_system(target: CertificateStoreTarget) -> Result<Self, StoreProviderError> {
            if target.name() != CertificateStoreName::My {
                return Err(StoreProviderError::Unsupported);
            }
            let flags = match target.location() {
                CertificateStoreLocation::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
                CertificateStoreLocation::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
            };
            // "My" is an in-process fixed allowlisted UTF-16 string, not a
            // pointer derived from untrusted request options or source paths.
            const MY: [u16; 3] = [b'M' as u16, b'y' as u16, 0];
            // SAFETY: provider tag is a Windows-defined constant; flags enforce
            // read-only existing system REGISTRY store access; pvPara points to
            // a properly terminated, alive UTF-16 buffer. No write handle used.
            let handle = unsafe {
                CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_REGISTRY_W,
                    0,
                    0,
                    flags | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG,
                    MY.as_ptr().cast::<c_void>(),
                )
            };
            if handle.is_null() {
                return Err(map_os_error());
            }
            Ok(Self(handle))
        }

        #[cfg(test)]
        fn open_memory() -> Result<Self, StoreProviderError> {
            // SAFETY: Memory provider creates a detached, ephemeral store only,
            // with no associated HKCU/HKLM backing registry or key container.
            let handle = unsafe { CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, ptr::null()) };
            if handle.is_null() {
                return Err(map_os_error());
            }
            Ok(Self(handle))
        }
    }
    impl Drop for OwnedStore {
        fn drop(&mut self) {
            // SAFETY: unique handle returned by CertOpenStore, closed exactly
            // once after all cursor contexts have been released.
            unsafe { CertCloseStore(self.0, 0) };
        }
    }

    /// Owns the current context until handed back to the Win32 enumerator or
    /// explicitly released on an interrupted traversal.
    struct OwnedContext(*const CERT_CONTEXT);
    impl Default for OwnedContext {
        fn default() -> Self {
            Self(ptr::null())
        }
    }
    impl OwnedContext {
        fn transfer_to_enumerator(&mut self) -> *const CERT_CONTEXT {
            std::mem::replace(&mut self.0, ptr::null())
        }
    }
    impl Drop for OwnedContext {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: context is still owned by this cursor, has not
                // already been consumed by CertEnumCertificatesInStore.
                unsafe { CertFreeCertificateContext(self.0) };
            }
        }
    }

    fn map_os_error() -> StoreProviderError {
        // SAFETY: GetLastError reads only the current thread's Win32 status.
        let code = unsafe { GetLastError() };
        if code == 5 {
            StoreProviderError::PermissionDenied
        } else {
            StoreProviderError::Io
        }
    }

    fn walk_store(
        store: &OwnedStore,
        visitor: &mut dyn FnMut(&[u8]) -> Result<(), StoreProviderError>,
    ) -> Result<(), StoreProviderError> {
        let mut previous = OwnedContext::default();
        loop {
            let prev = previous.transfer_to_enumerator();
            // SAFETY: the store handle is valid throughout this function.
            // CertEnumCertificatesInStore FREES prev (even on error);
            // ownership was transferred out of OwnedContext before this call.
            let next = unsafe { CertEnumCertificatesInStore(store.0, prev) };
            if next.is_null() {
                // SAFETY: inspect immediate Win32 status before any other API.
                let code = unsafe { GetLastError() };
                if code == CRYPT_E_NOT_FOUND || code == ERROR_NO_MORE_FILES {
                    return Ok(());
                }
                return Err(map_os_error());
            }
            previous = OwnedContext(next);
            // SAFETY: pointer returned from a successful Win32 enumeration is
            // live until next call or context release (both owned by cursor).
            let context = unsafe { &*next };
            let byte_count = context.cbCertEncoded as usize;
            if byte_count == 0 || byte_count > MAX_CERT_DER_BYTES {
                return Err(StoreProviderError::ResourceLimit);
            }
            if context.pbCertEncoded.is_null() {
                return Err(StoreProviderError::Malformed);
            }
            // SAFETY: Win32 cert context's encoded buffer remains alive while
            // OwnedContext owns it. Length was checked before creating slice.
            let der = unsafe { slice::from_raw_parts(context.pbCertEncoded, byte_count) };
            visitor(der)?;
        }
    }

    impl PublicCertificateStoreBackend for WindowsCertificateStoreBackend {
        fn visit(
            &self,
            target: CertificateStoreTarget,
            visitor: &mut dyn FnMut(&[u8]) -> Result<(), StoreProviderError>,
        ) -> Result<(), StoreProviderError> {
            let store = OwnedStore::open_system(target)?;
            walk_store(&store, visitor)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use cryptomap::collectors::certificate::parse_der;
        use windows_sys::Win32::Security::Cryptography::{
            CERT_STORE_ADD_ALWAYS, CertAddEncodedCertificateToStore, X509_ASN_ENCODING,
        };

        fn public_der(pem: &[u8]) -> Vec<u8> {
            use x509_cert::{
                Certificate,
                der::{DecodePem, Encode},
            };
            Certificate::from_pem(pem)
                .expect("fixture PEM")
                .to_der()
                .expect("fixture DER")
        }

        #[test]
        fn in_memory_native_enumeration_returns_only_bounded_public_der() {
            let rsa = public_der(include_bytes!(
                "../../cryptomap/examples/fixtures/certificate/rsa.pem"
            ));
            let ec = public_der(include_bytes!(
                "../../cryptomap/examples/fixtures/certificate/ec.pem"
            ));
            let store = OwnedStore::open_memory().expect("ephemeral store");
            for bytes in [&rsa, &ec] {
                // SAFETY: writes ONLY to ephemeral in-memory test store; the
                // public DER bytes are validated fixtures and in-bounds.
                let ok = unsafe {
                    CertAddEncodedCertificateToStore(
                        store.0,
                        X509_ASN_ENCODING,
                        bytes.as_ptr(),
                        u32::try_from(bytes.len()).unwrap(),
                        CERT_STORE_ADD_ALWAYS,
                        ptr::null_mut(),
                    )
                };
                assert_ne!(ok, 0);
            }
            let mut seen = Vec::<Vec<u8>>::new();
            walk_store(&store, &mut |bytes| {
                parse_der(bytes).map_err(|_| StoreProviderError::Malformed)?;
                seen.push(bytes.to_vec());
                Ok(())
            })
            .unwrap();
            seen.sort();
            let mut expected = vec![rsa, ec];
            expected.sort();
            assert_eq!(seen, expected);
        }

        #[test]
        fn aborted_memory_store_walk_frees_context_and_never_reads_system_store() {
            let der = public_der(include_bytes!(
                "../../cryptomap/examples/fixtures/certificate/rsa.pem"
            ));
            let store = OwnedStore::open_memory().unwrap();
            // SAFETY: isolated in-memory test store only.
            let added = unsafe {
                CertAddEncodedCertificateToStore(
                    store.0,
                    X509_ASN_ENCODING,
                    der.as_ptr(),
                    u32::try_from(der.len()).unwrap(),
                    CERT_STORE_ADD_ALWAYS,
                    ptr::null_mut(),
                )
            };
            assert_ne!(added, 0);
            let result = walk_store(&store, &mut |_| Err(StoreProviderError::Cancelled));
            assert_eq!(result, Err(StoreProviderError::Cancelled));
        }

        #[test]
        fn empty_ephemeral_native_store_is_complete_not_access_error() {
            let store = OwnedStore::open_memory().unwrap();
            let mut count = 0;
            walk_store(&store, &mut |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(count, 0);
        }
    }
}
