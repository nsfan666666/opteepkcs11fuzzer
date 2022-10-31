#include <pthread.h> // PTHREAD_MUTEX_INITIALIZER
#include <pkcs11_token.h> // pkcs11 client library help functions

#include "local_utils.h" // ARRAY_SIZE


#define PRI_FAIL(msg, ...) printf(msg "\n",__VA_ARGS__) // use printf instead of syslog

#ifndef __AFL_FUZZ_TESTCASE_LEN
  ssize_t fuzz_len;
  #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
  unsigned char fuzz_buf[1024000];
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_LOOP(x) ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
  #define __AFL_INIT() sync()
#endif

__AFL_FUZZ_INIT(); // ! AFL persistent mode (shm). Set AFL macro after includes

__AFL_COVERAGE(); // ! required for selective instrumentation feature to work

#define INPUT_SIZE 128 // fixed size buffer based on assumption about the max size that is likely to exercise all parts of the target function


/** ============================== harness =============================== **/

/*
 * Some PKCS#11 object resources used in the invocations
 */
static const CK_BYTE cktest_aes128_key[16];

// static const CK_BYTE cktest_aes128_iv[16];

/* HMACSHA256 (NIST) */
uint8_t hmacsha256key[] = "\xc1\xd6\x08\x14\x37\x6a\xae\x39\xc4\x11\x12\x46\x35\x34\x85\x95"
		"\x8f\x95\x55\x8f\xa3\x8f\xfc\x14\xe4\xa0\x98\x1d\x76\x24\x9b\x9f"
		"\x87\x63\xc4\xb3\xe2\xce\x4e\xf5";

// Supports: encrypt, decrypt, wrap, unwrap
// static CK_MECHANISM cktest_aes_cbc_mechanism = {
// 	CKM_AES_CBC,
// 	(CK_BYTE_PTR)cktest_aes128_iv, sizeof(cktest_aes128_iv),
// };

// Supports: key generation (a AES key generation mechanism)
static CK_MECHANISM cktest_aes_keygen_mechanism = {
	CKM_AES_KEY_GEN, NULL, 0,
};

// Supports: sign, verify, digest, key derivation
// static const CK_ULONG cktest_general_mechanism_hmac_len = 8;
// static CK_MECHANISM cktest_hmac_general_sha256_mechanism = {
// 	CKM_SHA256_HMAC_GENERAL, (CK_VOID_PTR)&cktest_general_mechanism_hmac_len,
// 	sizeof(CK_ULONG),
// };

// static const struct cktest_mac_cases[] = {
// 	{ .attr_key = cktest_hmac_md5_key, .attr_count = ARRAY_SIZE(cktest_hmac_md5_key), .mechanism = &cktest_hmac_md5_mechanism, .in_incr = 4, .in = mac_data_md5_in1, .in_len = ARRAY_SIZE(mac_data_md5_in1), .out = mac_data_md5_out1, .out_len = ARRAY_SIZE(mac_data_md5_out1), .multiple_incr = 0, }
// };

// Basic AES attribute template
#define CKTEST_AES_KEY \
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY}, sizeof(CK_OBJECT_CLASS) }, \
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) }, \
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },

static CK_ATTRIBUTE ck_test_generate_aes_object_encrypt_decrypt[] = {
	CKTEST_AES_KEY
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

/* Valid template to generate an all AES purpose key */
// static CK_ATTRIBUTE cktest_generate_aes_object[] = {
//	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY}, sizeof(CK_OBJECT_CLASS) },
//	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
//	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
// 	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
// 	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
// };

/* HMACsha256 */
static CK_ATTRIBUTE ck_test_import_hmac256_object_sign_verify[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY}, sizeof(CKO_SECRET_KEY) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_GENERIC_SECRET}, sizeof(CK_KEY_TYPE) },
	{ CKA_VALUE, &hmacsha256key, sizeof(hmacsha256key) },
	{ CKA_SIGN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VERIFY, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	// { CKA_ALLOWED_MECHANISMS, &hmac_allow_mech, sizeof(hmac_allow_mech) }
};

static CK_ATTRIBUTE ck_test_generate_aes_object_sign_verify[] = {
	CKTEST_AES_KEY
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_SIGN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VERIFY, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

/*
 * Util to find a slot on which to open a session
 */

static CK_RV close_lib(void)
{
	return C_Finalize(0);
}

static CK_RV init_lib_and_find_token_slot(CK_SLOT_ID *slot)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID_PTR slots = NULL;
	CK_ULONG count = 0;

	rv = C_Initialize(0);
	if (rv)
		return rv;

	rv = C_GetSlotList(CK_TRUE, NULL, &count);
	if (rv != CKR_OK)
		goto bail;

	if (count < 1) {
		rv = CKR_GENERAL_ERROR;
		goto bail;
	}

	slots = malloc(count * sizeof(CK_SLOT_ID));
	if (!slots) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = C_GetSlotList(CK_TRUE, slots, &count);
	if (rv)
		goto bail;

	/* Use the last slot */
	*slot = slots[count - 1];

bail:
	free(slots);
	if (rv)
		close_lib();

	return rv;
}

/*
 * Helpers for tests where we must log into the token.
 * These define the genuine PINs and label to be used with the test token.
 */

static CK_UTF8CHAR test_token_so_pin[] = { 
	0, 1, 2, 3, 4, 5, 6, 7, 8 , 9, 10, 
};

static CK_UTF8CHAR test_token_user_pin[] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
};
static CK_UTF8CHAR test_token_label[] = "PKCS11 TA test token";

static CK_RV init_test_token(CK_SLOT_ID slot)
{
	return C_InitToken(slot, test_token_so_pin, sizeof(test_token_so_pin),
			   test_token_label);
}

/* Login as user, eventually reset user PIN if needed */
static CK_RV init_user_test_token(CK_SLOT_ID slot)
{
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_RV rv = CKR_GENERAL_ERROR;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv)
		return rv;

	rv = C_Login(session, CKU_USER,	test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (rv == CKR_OK) {
		C_Logout(session);
		C_CloseSession(session);
		return rv;
	}

	rv = C_Login(session, CKU_SO, test_token_so_pin,
		     sizeof(test_token_so_pin));
	if (rv) {
		C_CloseSession(session);

		rv = init_test_token(slot);
		if (rv)
			return rv;

		rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
		if (rv)
			return rv;

		rv = C_Login(session, CKU_SO, test_token_so_pin,
			     sizeof(test_token_so_pin));
		if (rv) {
			C_CloseSession(session);
			return rv;
		}
	}

	rv = C_InitPIN(session, test_token_user_pin,
		       sizeof(test_token_user_pin));

	C_Logout(session);
	C_CloseSession(session);

	return rv;
}

/*
 * The memmem() function finds the start of the first occurrence of the
 * substring 'needle' of length 'nlen' in the memory area 'haystack' of
 * length 'hlen'.
 *
 * The return value is a pointer to the beginning of the sub-string, or
 * NULL if the substring is not found.
 */
void *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen)
{
    int needle_first;
    const void *p = haystack;
    size_t plen = hlen;

    if (!nlen)
        return NULL;

    needle_first = *(unsigned char *)needle;

    while (plen >= nlen && (p = memchr(p, needle_first, plen - nlen + 1)))
    {
        if (!memcmp(p, needle, nlen))
            return (void *)p;

        p++;
        plen = hlen - (p - haystack);
    }

    return NULL;
}

typedef struct b_pair {
    uint8_t *b1;
	size_t b1_sz;
	uint8_t *b2;
	size_t b2_sz;
} b_pair;

static bool split_buffer(const uint8_t *data, size_t data_sz, struct b_pair *buf_pair)
{
	size_t data_size;
	uint8_t *data_beg = data;
	uint8_t *data_end = data + data_sz;
	
	const uint8_t separator[] = {0xDE, 0xAD, 0xBE, 0xEF};
	size_t seperator_sz = ARRAY_SIZE(separator);
	uint8_t *seperator_beg;

	uint8_t *buf_1, *buf_2;
	size_t buf_1_sz, buf_2_sz;

	if (data_sz <= seperator_sz) {
		printf("split_buffer: data is too short to be separated\n");
		return false;
	}

	if ((seperator_beg = memmem(data_beg, data_sz, separator, seperator_sz)) == NULL) {
		printf("split_buffer: could not find separator\n");
		return false;
	}

	buf_1_sz = seperator_beg - data_beg;
	buf_2_sz = data_end - (seperator_beg + seperator_sz);

	if (!(buf_1 = malloc(buf_1_sz))) {  // ! needs to be freed
		printf("split_buffer: malloc buf_1 failed\n");
		return false;
	}

	if (!(buf_2 = malloc(buf_2_sz))) { // ! needs to be freed
		printf("split_buffer: malloc buf_2 failed\n");
		free(buf_1);
		return false;
	}

	memset(buf_pair, 0, sizeof(struct b_pair));
	memset(buf_1, 0, buf_1_sz);
	memset(buf_2, 0, buf_2_sz);

	memcpy(buf_1, data_beg, buf_1_sz);
	memcpy(buf_2, seperator_beg + seperator_sz, buf_2_sz);

	*buf_pair = (b_pair){ .b1 = buf_1, .b1_sz = buf_1_sz, .b2 = buf_2, .b2_sz = buf_2_sz };

	// print_hex(buf_pair->b1, buf_pair->b1_sz);
	// print_hex(buf_pair->b2, buf_pair->b2_sz);

	return true;
}

static uint8_t *afl_split_input(const uint8_t *afl_input, size_t afl_input_sz, size_t *data_sz, int *cmd) 
{
	uint8_t *tmp_bp;
	uint8_t *data;
	size_t data_size;
	

	if (afl_input_sz <= sizeof(*cmd)) {
		printf("afl input is too short to split\n");
		*data_sz = 0;
		return NULL;
	}
	
	data_size = afl_input_sz - sizeof(*cmd);
	*data_sz = data_size;

	data = malloc(data_size); // ! heap data that needs to be freed

	if (!data) {
		printf("ckteec_alloc_shm fail: CKR_HOST_MEMORY\n");
		*data_sz = 0;
		return NULL;
	}

	tmp_bp = afl_input;
	*cmd = *(int *) tmp_bp;

	if ( *cmd < 0 || *cmd > 52) {
		free(data);
		*data_sz = 0;
		return NULL;
	}

	memset(data, 0, data_size);
	tmp_bp = (int *) afl_input + 1;
	memcpy(data, tmp_bp, data_size);

	return data;
}


/* Create session object and token object from a session */
static void invoke_ta_no_args()
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hdl = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_lib_and_find_token_slot, rv=%lu", rv);
		return;
	}

	rv = close_lib();
	if (rv != CKR_OK)
		PRI_FAIL("close_lib, rv=%lu", rv);
}


/*
 * Harness sending TA data blobs without serialization
 */


/**
 * ckteec_invoke_ta - Invoke PKCS11 TA for a target request through the TEE
 *
 * @cmd - PKCS11 TA command ID
 * @ctrl - shared memory with serialized request input arguments or NULL
 * @io1 - In memory buffer argument #1 for the command or NULL
 * @io2 - In and/or out memory buffer argument #2 for the command or NULL
 * @out2_size - Reference to @io2 output buffer size or NULL if not applicable
 * @io3 - In and/or out memory buffer argument #3 for the command or NULL
 * @out3_size - Reference to @io3 output buffer size or NULL if not applicable
 *
 * Return a CR_RV compliant return value
 */



static CK_RV invoke_PKCS11_CMD_CREATE_OBJECT(const uint8_t *data, size_t data_sz, const CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR handle) {
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	uint32_t session_handle = session;
	uint32_t key_handle = 0;
	char *buf = NULL;
	size_t out_size = 0;

	if (!(session && handle))
		return CKR_ARGUMENTS_BAD;

	/* Prepare args for TA */
	/* Shm io0: (i/o) [session-handle][serialized-attributes] / [status] */
	
	ctrl = ckteec_alloc_shm(sizeof(session_handle) + data_sz, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		return CKR_HOST_MEMORY;
	}

	buf = ctrl->buffer; 

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, data, data_sz);

	/* Prepare shm to store output from TA */
	/* Shm io2: (out) [object handle] */
	
	out_shm = ckteec_alloc_shm(sizeof(key_handle), CKTEEC_SHM_OUT);
	if (!out_shm) {
		ckteec_free_shm(ctrl);
		return CKR_HOST_MEMORY;
	}

	/* Invoke TA with prepared args and shm */

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_CREATE_OBJECT, ctrl, 
					out_shm, &out_size);

	if (rv != CKR_OK || out_size != out_shm->size) {
		if (rv == CKR_OK)
			rv = CKR_DEVICE_ERROR;
		goto out;
	}

	memcpy(&key_handle, out_shm->buffer, sizeof(key_handle));
	*handle = key_handle;
	
out:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);
	return rv;
}

static CK_RV invoke_PKCS11_CMD_DECRYPT_INIT(void *data, size_t data_sz, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	uint32_t session_handle = session;
	uint32_t key_handle = key;
	size_t ctrl_size = 0;
	char *buf = NULL;

	if (!(session && key))
		return CKR_ARGUMENTS_BAD;

	/*
	 * Shm io0: (in/out) ctrl
	 * (in) [session-handle][key-handle][serialized-mechanism-blob]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + sizeof(key_handle) + data_sz;

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, &key_handle, sizeof(key_handle));
	buf += sizeof(key_handle);

	memcpy(buf, data, data_sz);

// printf("ctrl->size=%zu\n", ctrl->size);
// print_hex(ctrl->buffer, ctrl->size);

	rv = ckteec_invoke_ctrl(PKCS11_CMD_DECRYPT_INIT, ctrl);

bail:
	ckteec_free_shm(ctrl);

	return rv;
}

static CK_RV invoke_PKCS11_CMD_ENCRYPT_INIT(void *data, size_t data_sz, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	uint32_t session_handle = session;
	uint32_t key_handle = key;
	size_t ctrl_size = 0;
	char *buf = NULL;

	if (!(session && key))
		return CKR_ARGUMENTS_BAD;

	/*
	 * Shm io0: (in/out) ctrl
	 * (in) [session-handle][key-handle][serialized-mechanism-blob]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + sizeof(key_handle) + data_sz;

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, &key_handle, sizeof(key_handle));
	buf += sizeof(key_handle);

	memcpy(buf, data, data_sz);

	rv = ckteec_invoke_ctrl(PKCS11_CMD_ENCRYPT_INIT, ctrl);

bail:
	ckteec_free_shm(ctrl);

	return rv;
}

static CK_RV invoke_PKCS11_CMD_DIGEST_INIT(void *data, size_t data_sz, CK_SESSION_HANDLE session) {
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	uint32_t session_handle = session;
	size_t ctrl_size = 0;
	uint8_t *buf = NULL;

	if (!session)
		return CKR_ARGUMENTS_BAD;

	/*
	 * Shm io0: (in/out) ctrl
	 * (in) [session-handle][serialized-mechanism-blob]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + data_sz;
	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, data, data_sz);

	rv = ckteec_invoke_ctrl(PKCS11_CMD_DIGEST_INIT, ctrl);

bail:
	ckteec_free_shm(ctrl);

	return rv;
}

static CK_RV invoke_PKCS11_CMD_SIGN_INIT(void *data, size_t data_sz, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	uint32_t session_handle = session;
	uint32_t key_handle = key;
	size_t ctrl_size = 0;
	char *buf = NULL;

	if (!session)
		return CKR_ARGUMENTS_BAD;

	/*
	 * Shm io0: (in/out) ctrl
	 * (in) [session-handle][key-handle][serialized-mechanism-blob]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + sizeof(key_handle) + data_sz;
	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, &key_handle, sizeof(key_handle));
	buf += sizeof(key_handle);

	memcpy(buf, data, data_sz);

	rv = ckteec_invoke_ctrl(PKCS11_CMD_SIGN_INIT, ctrl);

bail:
	ckteec_free_shm(ctrl);

	return rv;
}

// static CK_RV invoke_PKCS11_CMD_VERIFY_INIT(void *data, size_t data_sz, CK_SESSION_HANDLE session) {

// }

static CK_RV invoke_PKCS11_CMD_GENERATE_KEY(void *data, size_t data_sz, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR handle) {
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	uint32_t session_handle = session;
	size_t ctrl_size = 0;
	uint32_t key_handle = 0;
	char *buf = NULL;
	size_t out_size = 0;

	if (!handle)
		return CKR_ARGUMENTS_BAD;

	/*
	 * Shm io0: (in/out) ctrl
	 * (in) [session-handle][serialized-mecha][serialized-attributes]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + data_sz;

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, data, data_sz);

	/* Shm io2: (out) [object handle] */
	out_shm = ckteec_alloc_shm(sizeof(key_handle), CKTEEC_SHM_OUT);
	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_GENERATE_KEY,
				    ctrl, out_shm, &out_size);

	if (rv != CKR_OK || out_size != out_shm->size) {
		if (rv == CKR_OK)
			rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	memcpy(&key_handle, out_shm->buffer, sizeof(key_handle));
	*handle = key_handle;

bail:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);

	return rv;
}

static CK_RV invoke_PKCS11_CMD_FIND_OBJECTS_INIT(void *data, size_t data_sz, CK_SESSION_HANDLE session) {
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	uint32_t session_handle = session;
	size_t ctrl_size = 0;
	char *buf = NULL;

	/* Shm io0: (in/out) ctrl
	 * (in) [session-handle][headed-serialized-attributes]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + data_sz;
	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, data, data_sz);

	rv = ckteec_invoke_ctrl(PKCS11_CMD_FIND_OBJECTS_INIT, ctrl);

bail:
	ckteec_free_shm(ctrl);

	return rv;
}

static CK_RV invoke_PKCS11_CMD_GET_ATTRIBUTE_VALUE(void *data, size_t data_sz, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj) {
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_RV rv2 = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	size_t ctrl_size = 0;
	uint32_t session_handle = session;
	uint32_t obj_handle = obj;
	char *buf = NULL;
	size_t out_size = 0;

	/* Shm io0: (in/out) [session][obj-handle][attributes] / [status] */
	ctrl_size = sizeof(session_handle) + sizeof(obj_handle) + data_sz;

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, &obj_handle, sizeof(obj_handle));
	buf += sizeof(obj_handle);

	memcpy(buf, data, data_sz);

	/* Shm io2: (out) [attributes] */
	out_shm = ckteec_alloc_shm(data_sz, CKTEEC_SHM_OUT);
	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_GET_ATTRIBUTE_VALUE,
				    ctrl, out_shm, &out_size);

	if (rv != CKR_OK) {
		PRI_FAIL("ckteec_invoke_ctrl_out, rv=%lu", rv);
		goto bail;
	}

bail:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);

	return rv;
}

// static CK_RV invoke_PKCS11_CMD_COPY_OBJECT(void *data, size_t data_sz, CK_SESSION_HANDLE session) {

// }

// static CK_RV invoke_PKCS11_CMD_DERIVE_KEY(void *data, size_t data_sz, CK_SESSION_HANDLE session) {

// }

static CK_RV invoke_PKCS11_CMD_GENERATE_KEY_PAIR(void *data, size_t data_sz, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR pub_key, CK_OBJECT_HANDLE_PTR priv_key) {
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	uint32_t session_handle = session;
	size_t ctrl_size = 0;
	uint32_t *key_handle = NULL;
	size_t key_handle_size = 2 * sizeof(*key_handle);
	char *buf = NULL;
	size_t out_size = 0;

	if (!(pub_key && priv_key))
		return CKR_ARGUMENTS_BAD;

	/*
	 * Shm io0: (in/out) ctrl
	 * (in) [session-handle][serialized-mecha][serialized-pub_attribs]
	 *      [serialized-priv_attribs]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + data_sz;

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, data, data_sz);

	/*
	 * Shm io2: (out) public key object handle][private key object handle]
	 */
	out_shm = ckteec_alloc_shm(key_handle_size, CKTEEC_SHM_OUT);
	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_GENERATE_KEY_PAIR,
				    ctrl, out_shm, &out_size);

	if (rv != CKR_OK || out_size != out_shm->size) {
		if (rv == CKR_OK)
			rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	key_handle = out_shm->buffer;
	*pub_key = key_handle[0];
	*priv_key = key_handle[1];

bail:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);

	return rv;
}

// static CK_RV invoke_PKCS11_CMD_WRAP_KEY(void *data, size_t data_sz, CK_SESSION_HANDLE session) {

// }

// static CK_RV invoke_PKCS11_CMD_UNWRAP_KEY(void *data, size_t data_sz, CK_SESSION_HANDLE session) {

// }

/* fuzzing ctrl serialized blob */
static void harness_PKCS11_CMD_CREATE_OBJECT(const uint8_t *data, size_t data_sz) {
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hdl = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	
	rv = init_lib_and_find_token_slot(&slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_lib_and_find_token_slot, rv=%lu", rv);
		return;
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv != CKR_OK) {
		PRI_FAIL("C_OpenSession, rv=%lu", rv);
		goto out;
	}
	
	rv = invoke_PKCS11_CMD_CREATE_OBJECT(data, data_sz, session, &obj_hdl);

	if (rv != CKR_OK) {
		PRI_FAIL("invoke_PKCS11_CMD_CREATE_OBJECT, rv=%lu", rv);
		goto out;
	}

out:
	rv = C_CloseSession(session);
	if (rv != CKR_OK)
		PRI_FAIL("C_CloseSession, rv=%lu", rv);

	rv = C_Finalize(0);
	if (rv != CKR_OK)
		PRI_FAIL("C_Finalize, rv=%lu", rv);
}

void harness_PKCS11_CMD_DECRYPT_INIT(void *data, size_t data_sz) {
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;

	uint8_t out[512] = { 0 };
	CK_ULONG out_len = 512;

	rv = init_lib_and_find_token_slot(&slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_lib_and_find_token_slot, rv=%lu", rv);
		return;
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv != CKR_OK) {
		PRI_FAIL("C_OpenSession, rv=%lu", rv);
		goto out;
	}

	/*
	 * Generate a 128 bit AES Secret Key.
	 * Initialize it for decryption.
	 */

	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism, ck_test_generate_aes_object_encrypt_decrypt, ARRAY_SIZE(ck_test_generate_aes_object_encrypt_decrypt), &key_handle);
	if (rv != CKR_OK) {
		PRI_FAIL("C_GenerateKey, rv=%lu", rv);
		goto err;
	}

	rv = invoke_PKCS11_CMD_DECRYPT_INIT(data, data_sz, session, &key_handle);
	if (rv != CKR_OK) {
		PRI_FAIL("invoke_PKCS11_CMD_DECRYPT_INIT, rv=%lu", rv);
		goto out;
	}

	rv = C_DecryptFinal(session, NULL, NULL);
	/* Only check that the operation is no more active */
	if (rv == CKR_BUFFER_TOO_SMALL) {
		PRI_FAIL("C_DecryptFinal, rv=%lu", rv);
		goto err;
	}

	rv = C_DestroyObject(session, key_handle);
	if (rv != CKR_OK) {
		PRI_FAIL("C_DestroyObject, rv=%lu", rv);
		goto err;
	}

	goto out;


err_destr_obj:
	rv = C_DestroyObject(session, key_handle);
	if (rv != CKR_OK)
		PRI_FAIL("C_DestroyObject, rv=%lu", rv);
err:
out:
	rv = C_CloseSession(session);
	if (rv != CKR_OK)
		PRI_FAIL("C_CloseSession, rv=%lu", rv);
close_lib:
	rv = C_Finalize(0);
	if (rv != CKR_OK)
		PRI_FAIL("C_Finalize, rv=%lu", rv);

}

/* Encrypt using a 128 bit AES secret key */
// 1010.4
void harness_PKCS11_CMD_ENCRYPT_INIT(void *data, size_t data_sz) {
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;

	uint8_t out[512] = { 0 };
	CK_ULONG out_len = 512;

	rv = init_lib_and_find_token_slot(&slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_lib_and_find_token_slot, rv=%lu", rv);
		return;
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv != CKR_OK) {
		PRI_FAIL("C_OpenSession, rv=%lu", rv);
		goto out;
	}

	/*
	 * Generate a 128 bit AES Secret Key.
	 * Initialize it for encyption.
	 */

	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism, ck_test_generate_aes_object_encrypt_decrypt, ARRAY_SIZE(ck_test_generate_aes_object_encrypt_decrypt), &key_handle);
	if (rv != CKR_OK) {
		PRI_FAIL("C_GenerateKey, rv=%lu", rv);
		goto err;
	}

	rv = invoke_PKCS11_CMD_ENCRYPT_INIT(data, data_sz, session, &key_handle);
	if (rv != CKR_OK) {
		PRI_FAIL("invoke_PKCS11_CMD_ENCRYPT_INIT, rv=%lu", rv);
		goto out;
	}

	rv = C_EncryptFinal(session, NULL, NULL);
	/* Only check that the operation is no more active */
	if (rv == CKR_BUFFER_TOO_SMALL) {
		PRI_FAIL("C_EncryptFinal, rv=%lu", rv);
		goto err;
	}

	rv = C_DestroyObject(session, key_handle);
	if (rv != CKR_OK) {
		PRI_FAIL("C_DestroyObject, rv=%lu", rv);
		goto err;
	}

	goto out;


err_destr_obj:
	rv = C_DestroyObject(session, key_handle);
	if (rv != CKR_OK)
		PRI_FAIL("C_DestroyObject, rv=%lu", rv);
err:
out:
	rv = C_CloseSession(session);
	if (rv != CKR_OK)
		PRI_FAIL("C_CloseSession, rv=%lu", rv);
close_lib:
	rv = C_Finalize(0);
	if (rv != CKR_OK)
		PRI_FAIL("C_Finalize, rv=%lu", rv);

}

void harness_PKCS11_CMD_DIGEST_INIT(void *data, size_t data_sz) {
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_lib_and_find_token_slot, rv=%lu", rv);
		return;
	}

	rv = init_test_token(slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_test_token, rv=%lu", rv);
		goto close_lib;
	}

	rv = init_user_test_token(slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_user_test_token, rv=%lu", rv);
		goto close_lib;
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv != CKR_OK){
		PRI_FAIL("C_OpenSession, rv=%lu", rv);
		goto close_lib;
	}

	/* Login to Test Token */
	rv = C_Login(session, CKU_USER,	test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (rv != CKR_OK){
		PRI_FAIL("C_Login, rv=%lu", rv);
		goto out;
	}

	rv = invoke_PKCS11_CMD_DIGEST_INIT(data, data_sz, session);

	if (rv != CKR_OK) {
		PRI_FAIL("invoke_PKCS11_CMD_DIGEST_INIT, rv=%lu", rv);
		goto out;
	}

out:
	rv = C_CloseSession(session);
	if (rv != CKR_OK)
		PRI_FAIL("C_CloseSession, rv=%lu", rv);
close_lib:
	rv = C_Finalize(0);
	if (rv != CKR_OK)
		PRI_FAIL("C_Finalize, rv=%lu", rv);
}

void harness_PKCS11_CMD_SIGN_INIT(void *data, size_t data_sz) {
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;
	CK_ATTRIBUTE_PTR attr_key;
	CK_ULONG attr_count;

	rv = init_lib_and_find_token_slot(&slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_lib_and_find_token_slot, rv=%lu", rv);
		return;
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv != CKR_OK){
		PRI_FAIL("C_OpenSession, rv=%lu", rv);
		goto err_close_lib;
	}

	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism, &ck_test_generate_aes_object_sign_verify, ARRAY_SIZE(ck_test_generate_aes_object_sign_verify), &key_handle);
	if (rv != CKR_OK) {
		PRI_FAIL("C_GenerateKey, rv=%lu", rv);
		goto err;
	}

	// rv = C_CreateObject(session, ck_test_import_hmac256_object_sign_verify, ARRAY_SIZE(ck_test_import_hmac256_object_sign_verify), &key_handle);
	// if (rv != CKR_OK) {
	// 	PRI_FAIL("Failed to create HMACsha256 object: %lu : 0x%x", rv, (uint32_t)rv);
	// 	return;
	// }

	rv = invoke_PKCS11_CMD_SIGN_INIT(data, data_sz, session, &key_handle);
	if (rv != CKR_OK) {
		PRI_FAIL("invoke_PKCS11_CMD_SIGN_INIT, rv=%lu", rv);
		goto err_destr_obj;
	}

	goto out;

err_destr_obj:
	rv = C_DestroyObject(session, key_handle);
	if (rv != CKR_OK)
		PRI_FAIL("C_DestroyObject, rv=%lu", rv);
err:
out:
	rv = C_CloseSession(session);
	if (rv != CKR_OK)
		PRI_FAIL("C_CloseSession, rv=%lu", rv);
err_close_lib:
	rv = C_Finalize(0);
	if (rv != CKR_OK)
		PRI_FAIL("C_Finalize, rv=%lu", rv);
}

// void harness_PKCS11_CMD_VERIFY_INIT(void *data, size_t data_sz) {

// }

void harness_PKCS11_CMD_GENERATE_KEY(void *data, size_t data_sz) {
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;

	rv = init_lib_and_find_token_slot(&slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_lib_and_find_token_slot, rv=%lu", rv);
		return;
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv != CKR_OK){
		PRI_FAIL("C_OpenSession, rv=%lu", rv);
		goto out;
	}

	rv = invoke_PKCS11_CMD_GENERATE_KEY(data, data_sz, session, &key_handle);

	if (rv != CKR_OK) {
		PRI_FAIL("invoke_PKCS11_CMD_CREATE_OBJECT, rv=%lu", rv);
		goto out;
	}

out:
	rv = C_CloseSession(session);
	if (rv != CKR_OK)
		PRI_FAIL("C_CloseSession, rv=%lu", rv);

	rv = C_Finalize(0);
	if (rv != CKR_OK)
		PRI_FAIL("C_Finalize, rv=%lu", rv);

}

void harness_PKCS11_CMD_FIND_OBJECTS_INIT(void *data, size_t data_sz) {
	// 1011
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	
	rv = init_lib_and_find_token_slot(&slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_lib_and_find_token_slot, rv=%lu", rv);
		return;
	}

	rv = init_test_token(slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_test_token, rv=%lu", rv);
		goto close_lib;
	}

	rv = init_user_test_token(slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_user_test_token, rv=%lu", rv);
		goto close_lib;
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv != CKR_OK){
		PRI_FAIL("C_OpenSession, rv=%lu", rv);
		goto close_lib;
	}

	rv = invoke_PKCS11_CMD_FIND_OBJECTS_INIT(data, data_sz, session);

	if (rv != CKR_OK) {
		PRI_FAIL("invoke_PKCS11_CMD_FIND_OBJECTS_INIT, rv=%lu", rv);
		goto out;
	}

out:
	rv = C_CloseSession(session);
	if (rv != CKR_OK)
		PRI_FAIL("C_CloseSession, rv=%lu", rv);
close_lib:
	rv = C_Finalize(0);
	if (rv != CKR_OK)
		PRI_FAIL("C_Finalize, rv=%lu", rv);
}

void harness_PKCS11_CMD_GET_ATTRIBUTE_VALUE(void *data, size_t data_sz) {
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE obj_hdl = CK_INVALID_HANDLE;

	rv = init_lib_and_find_token_slot(&slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_lib_and_find_token_slot, rv=%lu", rv);
		return;
	}

	rv = init_test_token(slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_test_token, rv=%lu", rv);
		goto close_lib;
	}

	rv = init_user_test_token(slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_user_test_token, rv=%lu", rv);
		goto close_lib;
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv != CKR_OK){
		PRI_FAIL("C_OpenSession, rv=%lu", rv);
		goto close_lib;
	}



	rv = invoke_PKCS11_CMD_GET_ATTRIBUTE_VALUE(data, data_sz, session, obj_hdl);

	if (rv != CKR_OK) {
		PRI_FAIL("invoke_PKCS11_CMD_GENERATE_KEY_PAIR, rv=%lu", rv);
		goto out;
	}

out:
	rv = C_CloseSession(session);
	if (rv != CKR_OK)
		PRI_FAIL("C_CloseSession, rv=%lu", rv);
close_lib:
	rv = C_Finalize(0);
	if (rv != CKR_OK)
		PRI_FAIL("C_Finalize, rv=%lu", rv);
}

// void harness_PKCS11_CMD_COPY_OBJECT(void *data, size_t data_sz) {

// }

// void harness_PKCS11_CMD_DERIVE_KEY(void *data, size_t data_sz) {

// }

void harness_PKCS11_CMD_GENERATE_KEY_PAIR(void *data, size_t data_sz) {
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;

	rv = init_lib_and_find_token_slot(&slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_lib_and_find_token_slot, rv=%lu", rv);
		return;
	}

	rv = init_test_token(slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_test_token, rv=%lu", rv);
		goto close_lib;
	}

	rv = init_user_test_token(slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_user_test_token, rv=%lu", rv);
		goto close_lib;
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv != CKR_OK){
		PRI_FAIL("C_OpenSession, rv=%lu", rv);
		goto close_lib;
	}

	/* Login to Test Token */
	rv = C_Login(session, CKU_USER,	test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (rv != CKR_OK){
		PRI_FAIL("C_Login, rv=%lu", rv);
		goto out;
	}

	rv = invoke_PKCS11_CMD_GENERATE_KEY_PAIR(data, data_sz, session, &public_key, &private_key);

	if (rv != CKR_OK) {
		PRI_FAIL("invoke_PKCS11_CMD_GENERATE_KEY_PAIR, rv=%lu", rv);
		goto out;
	}

out:
	rv = C_CloseSession(session);
	if (rv != CKR_OK)
		PRI_FAIL("C_CloseSession, rv=%lu", rv);
close_lib:
	rv = C_Finalize(0);
	if (rv != CKR_OK)
		PRI_FAIL("C_Finalize, rv=%lu", rv);
}


// void harness_PKCS11_CMD_WRAP_KEY(void *data, size_t data_sz) {

// }

// void harness_PKCS11_CMD_UNWRAP_KEY(void *data, size_t data_sz) {

// }


/* assume afl_buf being of format [slot-id][data] (could be wrong since its afl generated) */
void fuzz_ta(uint8_t *afl_input, size_t afl_input_sz) 
{
	uint8_t *data;
	size_t data_sz;
	int cmd;

	data = afl_split_input(afl_input, afl_input_sz, &data_sz, &cmd);
	
	if (!data) {
		printf("afl_split_input failed\n");
		goto bad_out;
	} 

	// printf("cmd=%d\n", cmd);
	// print_hex(data, data_sz);

	switch (cmd) {

	// case PKCS11_CMD_CREATE_OBJECT:
	// 	printf("fuzzing PKCS11_CMD_CREATE_OBJECT\n");
	// 	harness_PKCS11_CMD_CREATE_OBJECT(data, data_sz);
	// 	break;
	
	// // case PKCS11_CMD_DECRYPT_INIT:
	// // 	printf("fuzzing PKCS11_CMD_DECRYPT_INIT\n");
	// // 	harness_PKCS11_CMD_DECRYPT_INIT(data, data_sz);
	// // 	break;

	// case PKCS11_CMD_ENCRYPT_INIT:
	// 	// does not pass if (function != PKCS11_FUNCTION_DIGEST) in entry_processing_init ?
	// 	printf("fuzzing PKCS11_CMD_ENCRYPT_INIT\n");
	// 	harness_PKCS11_CMD_ENCRYPT_INIT(data, data_sz);
	// 	break;

	// case PKCS11_CMD_DIGEST_INIT:
	// 	printf("fuzzing PKCS11_CMD_DIGEST_INIT\n");
	// 	harness_PKCS11_CMD_DIGEST_INIT(data, data_sz);
	// 	break;

	// // case PKCS11_CMD_SIGN_INIT:
	// // 	printf("fuzzing PKCS11_CMD_SIGN_INIT\n");
	// // 	harness_PKCS11_CMD_SIGN_INIT(data, data_sz);
	// // 	break;

	// case PKCS11_CMD_GENERATE_KEY:
	// 	printf("fuzzing PKCS11_CMD_GENERATE_KEY\n");
	// 	// struct b_pair buffers;

	// 	// if (!split_buffer(data, data_sz, &buffers)) {
	// 	// 	printf("failed to split BUF\n");
	// 	// 	goto bad_out;
	// 	// }

	// 	// print_hex(buffers.b1, buffers.b1_sz);
	// 	// print_hex(buffers.b2, buffers.b2_sz);
		
	// 	harness_PKCS11_CMD_GENERATE_KEY(data, data_sz);

	// 	// free(buffers.b1);
	// 	// free(buffers.b2);
	// 	break;

	// case PKCS11_CMD_FIND_OBJECTS_INIT:
	// 	printf("fuzzing PKCS11_CMD_FIND_OBJECTS_INIT\n");
	// 	harness_PKCS11_CMD_FIND_OBJECTS_INIT(data, data_sz);
	// 	break;

	// case PKCS11_CMD_GET_ATTRIBUTE_VALUE:
	// 	printf("fuzzing PKCS11_CMD_GET_ATTRIBUTE_VALUE\n");
	// 	harness_PKCS11_CMD_GET_ATTRIBUTE_VALUE(data, data_sz);
	// 	break;

	// // case PKCS11_CMD_COPY_OBJECT:
	// // 	printf("fuzzing PKCS11_CMD_COPY_OBJECT\n");
	// // 	harness_PKCS11_CMD_COPY_OBJECT(data, data_sz);
	// // 	break;

	// // case PKCS11_CMD_DERIVE_KEY:
	// // 	printf("fuzzing PKCS11_CMD_DERIVE_KEY\n");
	// // 	harness_PKCS11_CMD_DERIVE_KEY(data, data_sz);
	// // 	break;

	// case PKCS11_CMD_GENERATE_KEY_PAIR:
	// 	printf("fuzzing PKCS11_CMD_GENERATE_KEY_PAIR\n");
	// 	harness_PKCS11_CMD_GENERATE_KEY_PAIR(data, data_sz);
	// 	break;

	// // case PKCS11_CMD_WRAP_KEY:
	// // 	printf("fuzzing PKCS11_CMD_WRAP_KEY\n");
	// // 	harness_PKCS11_CMD_WRAP_KEY(data, data_sz);
	// // 	break;

	// // case PKCS11_CMD_UNWRAP_KEY:
	// // 	printf("fuzzing PKCS11_CMD_UNWRAP_KEY\n");
	// // 	harness_PKCS11_CMD_UNWRAP_KEY(data, data_sz);
	// // 	break;

	default:
		printf("cmd is invalid\n");
		goto bad_out;

	}

	if (data)
		free(data);

	return;

bad_out:
	if (data)
		free(data);
		
	invoke_ta_no_args();
}


/** ============================== main =============================== **/

int main(int argc, char *argv[])
{
/* AFL persistent mode (input via shm), deferred forkserver */

#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT(); // defer forkserver
#endif

	uint8_t *afl_input = __AFL_FUZZ_TESTCASE_BUF; // Shm buf. MUST be after __AFL_INIT and before AFL_LOOP!

 	/* AFL loop */
	while(__AFL_LOOP(10000)) {
		int afl_input_sz = __AFL_FUZZ_TESTCASE_LEN; // DONT use the macro directly in a call

		fuzz_ta(afl_input, afl_input_sz);
	} // END _AFL_LOOP

	return 0;
}

