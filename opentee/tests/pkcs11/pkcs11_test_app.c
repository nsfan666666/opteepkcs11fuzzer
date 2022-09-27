//// #include <cryptoki.h>
#include "pkcs11.h" // cryptoki API 
#include <stdint.h> // some basic types and macros
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h> // for PATH_MAX
#include <sys/types.h> // pid_t
#include <unistd.h> // for STDIN_FILENO, fork, clone...
#include <errno.h>
#include <fcntl.h>

#include <pthread.h> // PTHREAD_MUTEX_INITIALIZER
#include <stdbool.h> // bool
#include <string.h> // memmem

#include "invoke_ta.h" // CKTEEC_SHM_INOUT, ckteec_alloc_shm
#include "tee_client_api.h" // TEEC_XXX, CK_XXX
#include "pkcs11_ta.h" // libdump
//// #include "local_utils.h" // ARRAY_SIZE

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

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#define PRI(str, ...)       printf("%s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_OK(str, ...)    printf(" [OK] : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_YES(str, ...)   printf(" YES? : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_FAIL(str, ...)  printf("FAIL  : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_ABORT(str, ...) printf("ABORT!: %s : " str "\n",  __func__, ##__VA_ARGS__);




// ! Print buffer in hexdump -C format

void print_hex(void *buf, size_t buf_sz)
{
	size_t i;
	for (i = 1; i <= buf_sz; ++i) {
  		printf("%02x ", ((uint8_t*) buf)[i-1]);

		if (i == 0) 
			continue;

		if (i % 8 == 0)
			printf(" ");

		if (i % 16 == 0)
			printf("\n");
	}
	printf("\n");
}





/** ============================== xtest =============================== **/

/*
 * Macros and structs
 * ==================
 */


struct ta_context {
	pthread_mutex_t init_mutex;
	bool initiated;
	TEEC_Context context;
	TEEC_Session session;
};

static struct ta_context ta_ctx = {
	.init_mutex = PTHREAD_MUTEX_INITIALIZER,
};

static const CK_BYTE cktest_aes128_key[16];

static CK_ATTRIBUTE cktest_token_object[] = {
	{ CKA_DECRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_TOKEN,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_CLASS,	&(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_VALUE,	(void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
};

static CK_ATTRIBUTE cktest_session_object[] = {
	{ CKA_DECRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_TOKEN,	&(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_CLASS,	&(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_VALUE,	(void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
};


#define ARRAY_SIZE(array)	(sizeof(array) / sizeof(array[0]))

/*
 * Utility functions
 * =================
 */

/*
 * Util to print CK_SESSION_INFO objects
 */
static void print_ck_session_info(CK_SESSION_INFO *session_info) 
{
	printf("\n");
	printf("session_info:\n");
	printf("\t{slotID=%lu}\n", session_info->slotID);
	printf("\t{state=%lu}\n", session_info->state);
	printf("\t{flags=%lu}\n", session_info->flags);
	printf("\t{ulDeviceError=%lu}\n", session_info->ulDeviceError);
	printf("\n");
}

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
	// printf("C_Initialize rv=%lu\n", rv);
	if (rv)
		return rv;

	rv = C_GetSlotList(CK_TRUE, NULL, &count);
	// printf("C_GetSlotList rv=%lu\n", rv);
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
	// printf("C_GetSlotList rv=%lu\n", rv);
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
static CK_UTF8CHAR test_token_so_pin[] = { 1, 2, 3, 4, };
static CK_UTF8CHAR test_token_user_pin[] = { 5, 6, 7, 8, };
static CK_UTF8CHAR test_token_label[] = "mytoken";

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




static CK_RV test_uninitialized_token(CK_SLOT_ID slot)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_TOKEN_INFO token_info = { };
	CK_FLAGS flags = 0;

	// C_InitToken() on uninitialized token BEGIN

	rv = init_test_token(slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_test_token, rv=%lu", rv);
		goto out;
	}

	rv = C_GetTokenInfo(slot, &token_info);
	if (rv != CKR_OK) {
		PRI_FAIL("C_GetTokenInfo, rv=%lu", rv);
		goto out;
	}

	flags = token_info.flags;

	if (!!(flags & CKF_TOKEN_INITIALIZED) != CK_TRUE ||
	    !(flags & CKF_ERROR_STATE) != CK_TRUE ||
	    !(flags & CKF_USER_PIN_INITIALIZED) != CK_TRUE) {
		rv = CKR_GENERAL_ERROR;
		goto out;
	}

	rv = init_user_test_token(slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_user_test_token, rv=%lu", rv);
		goto out;
	}

	rv = C_GetTokenInfo(slot, &token_info);
	if (rv != CKR_OK) {
		PRI_FAIL("C_GetTokenInfo, rv=%lu", rv);
		goto out;
	}

	flags = token_info.flags;

	if (!!(flags & CKF_TOKEN_INITIALIZED) != CK_TRUE ||
	    !(flags & CKF_USER_PIN_COUNT_LOW) != CK_TRUE ||
	    !(flags & CKF_USER_PIN_FINAL_TRY) != CK_TRUE ||
	    !(flags & CKF_USER_PIN_LOCKED) != CK_TRUE ||
	    !(flags & CKF_USER_PIN_TO_BE_CHANGED) != CK_TRUE ||
	    !!(flags & CKF_USER_PIN_INITIALIZED) != CK_TRUE ||
	    !(flags & CKF_ERROR_STATE) != CK_TRUE)
		rv = CKR_GENERAL_ERROR;

out:
	// C_InitToken() on uninitialized token END

	return rv;
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


/* Create session object and token object from a session */
static void test_create_destroy_single_object(bool persistent)
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
		
	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv != CKR_OK) {
		PRI_FAIL("C_OpenSession, rv=%lu", rv);
		goto out;
	}

	if (persistent) {
		rv = C_CreateObject(session, cktest_token_object,
				    ARRAY_SIZE(cktest_token_object),
				    &obj_hdl);
	} else {
		rv = C_CreateObject(session, cktest_session_object,
				    ARRAY_SIZE(cktest_session_object),
				    &obj_hdl);
	}

	if (rv != CKR_OK) {
		PRI_FAIL("C_CreateObject, rv=%lu", rv);
		goto out;
	}

	rv = C_DestroyObject(session, obj_hdl);
	if (rv != CKR_OK)
		PRI_FAIL("C_DestroyObject, rv=%lu", rv);
	
out:
	rv = C_CloseSession(session);
	if (rv != CKR_OK)
		PRI_FAIL("C_CloseSession, rv=%lu", rv);
	

	rv = close_lib();
	if (rv != CKR_OK)
		PRI_FAIL("close_lib, rv=%lu", rv);
}


/*
 * Test cases
 * ==========
 */

/*
 * List PKCS#11 slots and get information from the last slot
 */

static void xtest_pkcs11_test_1002(void)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session[3] = { 0 };
	CK_FLAGS session_flags = 0;
	CK_SESSION_INFO session_info = { };
	CK_FUNCTION_LIST_PTR ckfunc_list = NULL;

	printf("Initializing:\n");

	rv = init_lib_and_find_token_slot(&slot);

	if (rv != CKR_OK) {
		PRI_FAIL("init_lib_and_find_token_slot, rv=%lu", rv);
		goto bail;
	}

	rv = C_GetFunctionList(&ckfunc_list);
	if (rv != CKR_OK || ckfunc_list == NULL) {
		PRI_FAIL("C_GetFunctionList, rv=%lu", rv);
		goto bail;
	}

	session_flags = CKF_SERIAL_SESSION;
	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[0]);
	if (rv != CKR_OK) {
		PRI_FAIL("C_OpenSession (CKF_SERIAL_SESSION), rv=%lu", rv);
		goto bail;
	}

	rv = C_GetSessionInfo(session[0], &session_info);
	if (rv != CKR_OK) {
		PRI_FAIL("C_GetSessionInfo, rv=%lu", rv);
		goto bail;
	}

	print_ck_session_info(&session_info);

bail:
	rv = close_lib();
	if (rv != CKR_OK) {
		PRI_FAIL("close_lib, rv=%lu", rv);
		exit(EXIT_FAILURE);
	}
}


/*
 * PKCS11: Login to PKCS#11 token
 */

static void xtest_pkcs11_test_1003(void) 
{
	
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_FUNCTION_LIST_PTR ckfunc_list = NULL;
	CK_SLOT_ID slot = 0;
	CK_TOKEN_INFO token_info = { };

	// rv = C_GetFunctionList(&ckfunc_list);
	// if (rv != CKR_OK ||
	//     ckfunc_list->C_InitToken == NULL ||
	//     ckfunc_list->C_InitPIN == NULL ||
	//     ckfunc_list->C_SetPIN == NULL ||
	//     ckfunc_list->C_Login == NULL ||
	//     ckfunc_list->C_Logout == NULL)
	// 	goto out;

	rv = init_lib_and_find_token_slot(&slot);
	if (rv != CKR_OK) {
		PRI_FAIL("init_lib_and_find_token_slot, rv=%lu", rv);
		goto out;
	}

	rv = C_GetTokenInfo(slot, &token_info);
	if (rv != CKR_OK) {
		PRI_FAIL("C_GetTokenInfo, rv=%lu", rv);
		goto out;
	}

	/* Abort test if token is about to lock */
	if (!(token_info.flags & CKF_SO_PIN_FINAL_TRY) != CK_TRUE) {
		PRI_FAIL("token_info.flags", NULL);
		goto out;
	}

	if (!(token_info.flags & CKF_TOKEN_INITIALIZED)) {
		rv = test_uninitialized_token(slot);
		if (rv != CKR_OK) {
			PRI_FAIL("test_uninitialized_token, rv=%lu", rv);
			goto out;
		}
	}

	// // rv = test_already_initialized_token(slot);
	// // if (rv != CKR_OK) {
	// // 	PRI_FAIL("test_already_initialized_token, rv=%lu", rv);
	// // 	goto out;
	// // }

	// // rv = test_login_logout(slot);
	// // if (rv != CKR_OK) {
	// // 	PRI_FAIL("test_login_logout, rv=%lu", rv);
	// // 	goto out;
	// // }

	// // rv = test_set_pin(slot, CKU_USER);
	// // if (rv != CKR_OK) {
	// // 	PRI_FAIL("test_set_pin, rv=%lu", rv);
	// // 	goto out;
	// // }

	// // rv = test_set_pin(slot, CKU_SO);
	// // if (rv != CKR_OK) {
	// // 	PRI_FAIL("test_set_pin, rv=%lu", rv);
	// // 	goto out;
	// // }

	// // /*
	//  * CKU_CONTEXT_SPECIFIC is anything not CKU_USER or CKU_SO in order
	//  * to skip the initial login.
	//  */
	// test_set_pin(slot, CKU_CONTEXT_SPECIFIC);
out:
	rv = close_lib();
	
	if (rv != CKR_OK) {
		PRI_FAIL("close_lib, rv=%lu", rv);
	} 
}



/** ============================== generate corpus =============================== **/


void gen_corp_PKCS11_CMD_CREATE_OBJECT()
{
	test_create_destroy_single_object(false);
	// test_create_destroy_single_object(true);
}









/** ============================== harness =============================== **/

/*
 * Harness sending TA data blobs without serialization
 */


/* Create session object and token object from a session */
static void test_create_objects_in_session(bool readwrite)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE token_obj_hld = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE session_obj_hld = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!(rv == CKR_OK)) {
		printf("init_lib_and_find_token_slot failed\n");
		return;
	}

	if (readwrite)
		session_flags |= CKF_RW_SESSION;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!(rv == CKR_OK)) {
		printf("C_OpenSession failed\n");
		goto out;
	}

	rv = C_CreateObject(session, cktest_token_object,
			    ARRAY_SIZE(cktest_token_object),
			    &token_obj_hld);

	if (readwrite) {
		if (!(rv == CKR_OK)) {
			printf("C_CreateObject (token object) failed\n");
			goto out;
		}
	} else {
		if (!(rv == CKR_SESSION_READ_ONLY)) {
			printf("C_CreateObject failed (token object) due to CKR_SESSION_READ_ONLY\n");
			goto out;
		}
	}

	rv = C_CreateObject(session, cktest_session_object,
			    ARRAY_SIZE(cktest_session_object),
			    &session_obj_hld);

	if (!(rv == CKR_OK)) {
			printf("C_CreateObject (session object) failed\n");
			goto out_tobj;
		}

	rv = C_DestroyObject(session, session_obj_hld);
	if (!(rv == CKR_OK))
		printf("C_DestroyObject (session object) failed\n");

out_tobj:
	if (readwrite) {
		rv = C_DestroyObject(session, token_obj_hld);
		if (!(rv == CKR_OK))
			printf("C_DestroyObject (token object) failed\n");
	}
out:
	rv = C_CloseSession(session);
	if (!(rv == CKR_OK))
		printf("C_CloseSession failed\n");

	rv = close_lib();
	if (!(rv == CKR_OK))
		printf("close_lib failed\n");
}


CK_RV invoke_PKCS11_CMD_CREATE_OBJECT(void *data, size_t data_sz, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR handle) {
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	
	uint32_t session_handle = session;
	uint32_t key_handle = 0;

	char *tmp_bp = NULL; // temp. buffer pointer
	size_t out_size = 0;

	/* Prepare args for TA */
	/* Shm io0: (i/o) [session-handle][serialized-attributes] / [status] */
	
	ctrl = ckteec_alloc_shm(sizeof(session_handle) + data_sz, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		return CKR_HOST_MEMORY;
	}

	tmp_bp = ctrl->buffer; 

	memcpy(tmp_bp, &session_handle, sizeof(session_handle));
	tmp_bp += sizeof(session_handle);

	memcpy(tmp_bp, data, data_sz);

	/* Prepare shm to store output from TA */
	/* Shm io2: (out) [object handle] */
	
	out_shm = ckteec_alloc_shm(sizeof(key_handle), CKTEEC_SHM_OUT);
	if (!out_shm) {
		ckteec_free_shm(ctrl);
		return CKR_HOST_MEMORY;
	}

	/* Invoke TA with prepared args and shm */

	// printf("cmd=%d\n", PKCS11_CMD_CREATE_OBJECT);
	// print_hex(ctrl->buffer, ctrl->size);
	printf("PKCS11_CMD_CREATE_OBJECT\n");

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


	// res = TEEC_InvokeCommand(&ta_ctx.session, cmd, &op, &origin);
}

/* fuzzing ctrl serialized blob */
void harness_PKCS11_CMD_CREATE_OBJECT(void *data, size_t data_sz) {
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

	rv = close_lib();
	if (rv != CKR_OK)
		PRI_FAIL("close_lib, rv=%lu", rv);
}

TEEC_SharedMemory * afl_split_input(void *afl_input, size_t afl_input_sz, size_t *data_sz, int *cmd) 
{
	void *tmp_bp;
	size_t data_size;
	TEEC_SharedMemory *data;

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

/* assume afl_buf being of format [slot-id][data] (could be wrong since its afl generated) */
void fuzz_ta(void *afl_input, size_t afl_input_sz) 
{

	TEEC_SharedMemory *data;
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

	case PKCS11_CMD_CREATE_OBJECT:
		printf("fuzzing PKCS11_CMD_CREATE_OBJECT\n");
		harness_PKCS11_CMD_CREATE_OBJECT(data, data_sz);
		break;

	default:
		printf("cmd is invalid\n");
		if (data)
			free(data);
		goto bad_out;

	}

	if (data)
		free(data);

	return;

bad_out:
	invoke_ta_no_args();
}


/** ============================== main =============================== **/








int main(int argc, char *argv[])
{



/* AFL persistent mode (input via shm), deferred forkserver */

#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT(); // defer forkserver
#endif

	unsigned char *afl_input = __AFL_FUZZ_TESTCASE_BUF; // Shm buf. MUST be after __AFL_INIT and before AFL_LOOP!

// 	/* AFL loop */
	while(__AFL_LOOP(10000)) {
		int afl_input_sz = __AFL_FUZZ_TESTCASE_LEN; // DONT use the macro directly in a call

		printf("***************************************\n");

		// print_hex(afl_input, afl_input_sz);
		fuzz_ta(afl_input, afl_input_sz);

		printf("***************************************\n");

	} // END _AFL_LOOP

	return 0;
}

