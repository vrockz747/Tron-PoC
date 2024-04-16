/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.9-dev */

#ifndef PB_PROTOCOL_TEST_PB_H_INCLUDED
#define PB_PROTOCOL_TEST_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

/* Struct definitions */
typedef struct _protocol_test {
    int64_t expiration;
    int64_t timestamp;
} protocol_test;


#ifdef __cplusplus
extern "C" {
#endif

/* Initializer values for message structs */
#define protocol_test_init_default               {0, 0}
#define protocol_test_init_zero                  {0, 0}

/* Field tags (for use in manual encoding/decoding) */
#define protocol_test_expiration_tag             8
#define protocol_test_timestamp_tag              18

/* Struct field encoding specification for nanopb */
#define protocol_test_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, INT64,    expiration,        8) \
X(a, STATIC,   SINGULAR, INT64,    timestamp,        18)
#define protocol_test_CALLBACK NULL
#define protocol_test_DEFAULT NULL

extern const pb_msgdesc_t protocol_test_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define protocol_test_fields &protocol_test_msg

/* Maximum encoded size of messages (where known) */
#define PROTOCOL_TEST_PB_H_MAX_SIZE              protocol_test_size
#define protocol_test_size                       23

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif