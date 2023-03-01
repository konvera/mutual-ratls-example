package main

// #cgo LDFLAGS: -ldl
// #include <assert.h>
// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <string.h>
//
// /* expected SGX measurements in binary form */
// static char g_expected_mrenclave[32];
// static char g_expected_mrsigner[32];
// static char g_expected_isv_prod_id[2];
// static char g_expected_isv_svn[2];
//
// static bool g_verify_mrenclave   = false;
// static bool g_verify_mrsigner    = false;
// static bool g_verify_isv_prod_id = false;
// static bool g_verify_isv_svn     = false;
//
// /* RA-TLS: our own callback to verify SGX measurements */
// static int my_verify_measurements(const char* mrenclave, const char* mrsigner,
//                                   const char* isv_prod_id, const char* isv_svn) {
//     assert(mrenclave && mrsigner && isv_prod_id && isv_svn);
//
//     if (g_verify_mrenclave &&
//             memcmp(mrenclave, g_expected_mrenclave, sizeof(g_expected_mrenclave)))
//         return -1;
//
//     if (g_verify_mrsigner &&
//             memcmp(mrsigner, g_expected_mrsigner, sizeof(g_expected_mrsigner)))
//         return -1;
//
//     if (g_verify_isv_prod_id &&
//             memcmp(isv_prod_id, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id)))
//         return -1;
//
//     if (g_verify_isv_svn &&
//             memcmp(isv_svn, g_expected_isv_svn, sizeof(g_expected_isv_svn)))
//         return -1;
//
//     return 0;
// }
//
// int ra_tls_verify_callback_der_wrapper(void *f, u_int8_t* der_crt, size_t der_crt_size) {
//     
//     int (*ra_tls_verify_callback_der)(u_int8_t*, size_t); 
//     ra_tls_verify_callback_der = (int (*)(u_int8_t*, size_t))f;
//     return ra_tls_verify_callback_der(der_crt,der_crt_size);
// }
//
// void ra_tls_set_measurement_callback_wrapper(void *f) {
//     void (*ra_tls_set_measurement_callback)(int (*)(const char*, const char*, const char*, const char*));
//     ra_tls_set_measurement_callback = (void (*)(int (*)(const char*, const char*, const char*, const char*)))f;
//     ra_tls_set_measurement_callback(my_verify_measurements);
// }
import "C"

import (
	"fmt"
	"time"
	"unsafe"
)

func ra_tls_verify(cert []byte) (error) {

	helper_sgx_urts_lib_name := C.CString("libsgx_urts.so")
	defer C.free(unsafe.Pointer(helper_sgx_urts_lib_name))
	helper_sgx_urts_lib := C.dlopen(helper_sgx_urts_lib_name, C.RTLD_LAZY)
	if helper_sgx_urts_lib == nil {
		return fmt.Errorf("error opening %q", helper_sgx_urts_lib_name)
	}
	defer func() {
		if r := C.dlclose(helper_sgx_urts_lib); r != 0 {
			fmt.Errorf("error closing %q", helper_sgx_urts_lib_name)
		}
	}()

	ra_tls_verify_lib_name := C.CString("libra_tls_verify_dcap.so")
	defer C.free(unsafe.Pointer(ra_tls_verify_lib_name))
	ra_tls_verify_lib := C.dlopen(ra_tls_verify_lib_name, C.RTLD_LAZY)
	if ra_tls_verify_lib == nil {
		return fmt.Errorf("error opening %q", ra_tls_verify_lib_name)
	}
	defer func() {
		if r := C.dlclose(ra_tls_verify_lib); r != 0 {
			fmt.Errorf("error closing %q", ra_tls_verify_lib_name)
		}
	}()

	ra_tls_verify_callback_der_sym := C.CString("ra_tls_verify_callback_der")
	defer C.free(unsafe.Pointer(ra_tls_verify_callback_der_sym))
	ra_tls_verify_callback_der_f := C.dlsym(ra_tls_verify_lib, ra_tls_verify_callback_der_sym)
	if ra_tls_verify_callback_der_f == nil {
		return fmt.Errorf("error resolving %q function", ra_tls_verify_callback_der_sym)
	}

	ra_tls_set_measurement_callback_sym := C.CString("ra_tls_set_measurement_callback")
	defer C.free(unsafe.Pointer(ra_tls_set_measurement_callback_sym))
	ra_tls_set_measurement_callback_f := C.dlsym(ra_tls_verify_lib, ra_tls_set_measurement_callback_sym)
	if ra_tls_set_measurement_callback_f == nil {
		return fmt.Errorf("error resolving %q function", ra_tls_set_measurement_callback_sym)
	}

	C.ra_tls_set_measurement_callback_wrapper(ra_tls_set_measurement_callback_f)

	start := time.Now()

	cert_size := C.size_t(len(cert))
	certDER_sym := C.CBytes(cert)
	defer C.free(unsafe.Pointer(certDER_sym))
	ret := C.ra_tls_verify_callback_der_wrapper(ra_tls_verify_callback_der_f, (*C.uchar)(certDER_sym), cert_size)

	fmt.Printf("RA TLS took %s\n", time.Since(start))

	if ret == 0 {
		return nil
	}

	return fmt.Errorf("attestation failed")
}
