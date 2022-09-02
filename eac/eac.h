/*
 * Copyright (c) 2010-2012 Frank Morgner and Dominik Oepen
 *
 * This file is part of OpenPACE.
 *
 * OpenPACE is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * OpenPACE is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * OpenPACE.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with OpenSSL (or a modified version of that library), containing
 * parts covered by the terms of OpenSSL's license, the licensors of
 * this Program grant you additional permission to convey the resulting work.
 * Corresponding Source for a non-source form of such a combination shall include
 * the source code for the parts of OpenSSL used as well as that of the
 * covered work.
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with OpenSC (or a modified version of that library), containing
 * parts covered by the terms of OpenSC's license, the licensors of
 * this Program grant you additional permission to convey the resulting work. 
 * Corresponding Source for a non-source form of such a combination shall include
 * the source code for the parts of OpenSC used as well as that of the
 * covered work.
 */

/**
 * @file eac.h
 * @brief Interface for Extended Access Control
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef EAC_H_
#define EAC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "fido_sgx_sod_dg.h"

#include <eac/objects.h>
#include <openssl/asn1.h>
#include <openssl/buffer.h>
#include <openssl/cmac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

/** @defgroup management Data Management and Initialization
 *  @defgroup printing Data Printing
 *  @defgroup eacproto Protocol Steps for Extended Access Control
 *  @{
 *      @defgroup paceproto  Protocol Steps for Password Authenticated Connection Establishment
 *      @defgroup taproto Protocol Steps for Terminal Authentication
 *      @defgroup caproto Protocol Steps for Chip Authentication
 *      @defgroup riproto Protocol Steps for Restricted Authentication
 *  @}
 *  @defgroup sm Cryptographic Wrappers for Secure Messaging
 */


/**
 * @brief Identification of the specifications to use.
 *
 * @note TR-03110 v2.01 differs from all later versions of the Technical
 * Guideline in how the authentication token is calculated. Therefore old test
 * cards are incompatible with the newer specification.
 */
enum eac_tr_version {
    /** @brief Undefined type, if nothing else matches */
    EAC_TR_VERSION = 0,
    /** @brief Perform EAC according to TR-03110 v2.01 */
    EAC_TR_VERSION_2_01,
    /** @brief Perform EAC according to TR-03110 v2.02 and later */
    EAC_TR_VERSION_2_02,
};


/** @brief TR-03110 always uses CMAC of 8 bytes length for AES MAC */
#define EAC_AES_MAC_LENGTH 8

/**
 * @addtogroup management
 *
 * @{ ************************************************************************/

/**
 * @brief Initializes OpenSSL and the EAC identifier
 *
 * @see \c OpenSSL_add_all_algorithms()
 */
void EAC_init(void);

/**
 * @brief Wrapper to \c EVP_cleanup()
 */
void EAC_cleanup(void);

/**
 * @brief Create a new EAC context
 * @return New EAC context or NULL in case of an error
 */
EPASS_CTX *
EPASS_CTX_new(void);

/**
 * @brief Free an EAC context.
 *
 * Sensitive memory is cleared with OPENSSL_cleanse().
 *
 * @param[in] ctx EAC context to free
 */
void EPASS_CTX_clear_free(EPASS_CTX *ctx);


/**
 * @brief Initialize an EAC context for PACE, TA and CA from the data
 * given in an \c EF.CardAccess
 *
 * @param[in] in \c EF.CardAccess
 * @param[in] in_len Length of \a in
 * @param[in,out] ctx EAC context to initialize
 *
 * @return 1 on success or 0 in case of an error
 */
int EPASS_CTX_init_ef_cardaccess(unsigned const char * in, size_t in_len,
        EPASS_CTX *ctx);

/**
 * @brief Initialize an EAC context for PACE, TA and CA from the data
 * given in an \c EF.CardSecurity
 *
 * Performs passive authentication if required.
 *
 * @param[in] ef_cardsecurity buffer containing the ASN.1 encoded EF.CardSecurity
 * @param[in] ef_cardsecurity_len length of \a ef_cardsecurity
 * @param[in,out] ctx EAC context to initialize
 *
 * @return 1 on success or 0 in case of an error
 */
int EPASS_CTX_init_ef_cardsecurity(
        const unsigned char *ef_cardsecurity, size_t ef_cardsecurity_len,
        EPASS_CTX *ctx);

/**
 * @brief Get the CSCA lookup callback
 *
 * @param[in] ctx EAC context
 * @param[in,out] lookup_cvca_cert lookup callback
 *
 * @return 1 on success or 0 in case of an error
 */
int EPASS_CTX_get_csca_lookup_cert(const EPASS_CTX *ctx, X509_lookup_csca_cert *lookup_cvca_cert);
/**
 * @brief Set the CSCA lookup callback
 *
 * @param[in] ctx EAC context
 * @param[in] lookup_cvca_cert lookup callback
 *
 * @return 1 on success or 0 in case of an error
 */
int EPASS_CTX_set_csca_lookup_cert(EPASS_CTX *ctx, X509_lookup_csca_cert lookup_cvca_cert);
/**
 * @brief Return the default lookup of the country signing CA
 *
 * The default callback looks at /etc/eac/$chr for the CVCA
 * certificate, where $chr is the card holder reference of the CVCA.
 *
 * @return default lookup of the country verifying CA
 */
X509_lookup_csca_cert EAC_get_default_csca_lookup(void);

/**
 * @brief Set directory for \c EAC_get_default_csca_lookup()
 *
 * @param x509_default_dir
 */
void EAC_set_x509_default_dir(const char *default_dir);

/** @} ***********************************************************************/

/**
 * @addtogroup sm
 *
 * @{ ************************************************************************/

/**
 * @brief Pad a buffer using ISO/IEC 9797-1 padding method 2.
 *
 * The block size is calculated from the currently selected SM context.
 *
 * @param[in] ctx EAC context
 * @param[in] unpadded Buffer to pad
 *
 * @return Padded input or NULL in case of an error
 */
BUF_MEM *
EAC_add_iso_pad(const EPASS_CTX *ctx, const BUF_MEM * unpadded);
/**
 * @brief Remove ISO/IEC 9797-1 padding method 2 from a message
 *
 * @param[in] padded Padded message
 *
 * @return Unpadded message or NULL in case of an error
 */
BUF_MEM *
EAC_remove_iso_pad(const BUF_MEM * padded);

/**
 * @brief Increment the Send Sequence Counter
 *
 * @param ctx
 *
 * @return 1 on success or 0 in case of an error
 */
int EAC_increment_ssc(const EPASS_CTX *ctx);

/**
 * @brief Reset the Send Sequence Counter
 *
 * @param ctx
 *
 * @return 1 on success or 0 in case of an error
 */
int EAC_reset_ssc(const EPASS_CTX *ctx);
/**
 * @brief Set the Send Sequence Counter
 *
 * @param ctx
 * @param ssc
 *
 * @return 1 on success or 0 in case of an error
 */
int EAC_set_ssc(const EPASS_CTX *ctx, unsigned long ssc);

/**
 * @brief Encrypts data according to TR-03110 F.2.
 *
 * @param[in] ctx EAC context
 * @param[in] data Data to encrypt
 *
 * @return Encrypted data or NULL in case of an error
 *
 * @note \a data must already be padded to block length
 */
BUF_MEM *
EAC_encrypt(const EPASS_CTX *ctx, const BUF_MEM *data);

/**
 * @brief Decrypt data according to TR-03110 F.2.
 *
 * @param[in] ctx EAC context
 * @param[in] data Data to decrypt
 *
 * @return Decrypted data or NULL in case of an error
 *
 * @note \a data must already be padded to block length
 */
BUF_MEM *
EAC_decrypt(const EPASS_CTX *ctx, const BUF_MEM *data);

/**
 * @brief Authenticate data according to TR-03110 F.2.
 *
 * @param[in] ctx EAC context
 * @param[in] data Data to authenticate
 *
 * @return MAC or NULL in case of an error
 *
 * @note \a data must already be padded to block length
 */
BUF_MEM *
EAC_authenticate(const EPASS_CTX *ctx, const BUF_MEM *data);
/**
 * @brief Verify authenticated data according to TR-03110 F.2
 *
 * @param[in] ctx EAC context
 * @param[in] data Data to authenticate
 * @param[in] mac The MAC that is going to be verified
 *
 * @return 1 if the MAC can be correctly verified, 0 otherwise
 */
int
EAC_verify_authentication(const EPASS_CTX *ctx, const BUF_MEM *data,
        const BUF_MEM *mac);

/**
 * @brief Compresse a public key according to TR-03110 Table A.2.
 *
 * @param[in] ctx EAC context
 * @param[in] id accepts \c EAC_ID_PACE, \c EAC_ID_CA, \c EAC_ID_TA
 * @param[in] pub Raw public key
 *
 * @return Compressed public key or NULL in case of an error
 */
BUF_MEM *
EAC_Comp(const EPASS_CTX *ctx, int id, const BUF_MEM *pub);

/**
 * @brief Compute the hash of a CV certificate description.
 *
 * The hash can then be compared to the hash contained in the corresponding CV
 * certificate.
 *
 * @param[in] cert_desc ASN1 encoded CV certificate description
 * @param[in] cert_desc_len Length of \a cert_desc
 *
 * @return Hash of \a cert_desc or NULL in case of an error
 */
BUF_MEM *
EAC_hash_certificate_description(const unsigned char *cert_desc,
        size_t cert_desc_len);

/** @brief Identifies the PACE context */
#define EAC_ID_PACE 0
/** @brief Identifies the CA context */
#define EAC_ID_CA 1
/** @brief Identifies the TA context */
#define EAC_ID_TA 2
/** @brief Identifies the currently used channel for encryption/decryption */
#define EAC_ID_EAC 3

/**
 * @brief Set the SM context for encryption, decryption and authentication.
 *
 * Calls \a EAC_reset_ssc()
 *
 * @param[in,out] ctx EAC context
 * @param[in] id accepts \c EAC_ID_PACE, \c EAC_ID_CA, \c EAC_ID_EAC
 *
 * @return 1 on success or 0 in case of an error
 */
int
EPASS_CTX_set_encryption_ctx(EPASS_CTX *ctx, int id);

/** @} ***********************************************************************/

/**
 * @addtogroup printing
 *
 * @{ ************************************************************************/

/**
 * @brief Print EAC context including private data.
 *
 * @param[in] out Where to print the data
 * @param[in] ctx EAC context to be printed
 * @param[in] indent Number of whitespaces used for indenting the output
 *
 * @return 1 on success or 0 in case of an error
 */
int EPASS_CTX_print_private(BIO *out, const EPASS_CTX *ctx, int indent);
/**
 * @brief Prints buffer
 *
 * @param[in] out Where to print the data
 * @param[in] buf Buffer to print
 * @param[in] indent Number of whitespaces used for indenting the output
 *
 * @return 1 on success or 0 in case of an error
 */
int BUF_MEM_print(BIO *out, const BUF_MEM *buf, int indent);

/**
 * @brief Frees and wipes a buffer
 *
 * Calls \c OPENSSL_cleanse() and \c BUF_MEM_free().
 *
 * @param[in] b Where to print the data
 *
 */
void
BUF_MEM_clear_free(BUF_MEM *b);

/** @} ***********************************************************************/
#ifdef __cplusplus
}
#endif
#endif
