/*
 * This file is Copyright Santiago Torres Arias <torresariass@gmail.com> 2014 
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 *
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef LIBPOLYPASSHASH_H
#define LIBPOLYPASSHASH_H

#include "libgfshare.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <string.h>

/* Constant Declaration */
#define SHARE_LENGTH 256/8              // the length of our share buffers
#define DIGEST_LENGTH SHARE_LENGTH
#define MAX_NUMBER_OF_SHARES 256        // the maximum number of shares
#define USERNAME_LENGTH 128             // the maximum username length
#define SALT_LENGTH 16                  // the length of the salt to be used
#define PASSWORD_LENGTH 128             // I'm setting this as for the PHC

/* Custom types */ 
typedef unsigned char uint8;

/* enums */
typedef enum{
  // all goes good
  PPH_ERROR_OK = 0,
  // accounts go bad
  PPH_USERNAME_IS_TOO_LONG,
  PPH_PASSWORD_IS_TOO_LONG,
  PPH_ACCOUNT_IS_INVALID,
  PPH_WRONG_SHARE_COUNT,
  // system or user is being brilliant. 
  PPH_NO_MEM,
  PPH_BAD_PTR,
  PPH_PTR_IS_NULL,
  // developer is not brilliant
  PPH_ERROR_UNKNOWN,
}PPH_ERROR;

/* structure definitions */
// this might sound like little overkill, but it will help us keep the code
// tidier
typedef struct _shamir_share{
  uint8 *data;                  // the data to hold
  uint8 share_number;           // the share that corresponds to this data
}shamir_share;


typedef struct _pph_entry{
  uint8 share_number;           // the share number that belongs to this entry
  uint8 salt[SALT_LENGTH];      // the salt buffer to use 
  uint8 hashed_value[DIGEST_LENGTH];// the hashed password of this value
  struct _pph_entry *next;
} pph_entry;


typedef struct _pph_account{
  unsigned char username[USERNAME_LENGTH]; // the username...
  uint8 number_of_entries;                 // the entries for this user
  pph_entry *entries;                      // a pointer to entries of this acc
}pph_account;

// I decided to keep this structure as a separate one for cleanliness and
// easy refactoring. 
typedef struct _pph_account_node{  // we will hold user data in a dynamic list
  struct _pph_account_node* next;
  pph_account account;
}pph_account_node;

typedef struct _pph_context{
  gfshare_ctx *share_context;    // this is a pointer to the libgfshare engine
  uint8 threshold;               // the threshold set to the libgfshare engine
  uint8 available_shares;        // this is the number of available shares
  uint8 is_unlocked;             // this is a boolean flag indicating whether 
                                 //  the secret is known.
  uint8 *AES_key;                // a randomly generated AES key of SHARE_LENGTH
  uint8 *secret;                 // secret data, this is sent by the user
  uint8 partial_bytes;           // partial bytes, if 0, thresholdless is
                                 //   disabled
  shamir_share* shares;          // this will point to a malloc'ed array of 
                                 //  shares
  pph_account_node* account_data;// we will hold a reference to the account
                                 //  data in here
  uint8 next_entry;              // this allocates shares in a round-robin 
                                 //  fashion
}pph_context;


/* Function Declarations */
/*******************************************************************
* NAME :            pph_init_conext
*
* DESCRIPTION :     Initialize a poly pass hash structure with everything
*                   we need in order to work. Custom initialization is to
*                   be provided
*
* INPUTS :
*   PARAMETERS:
*     uint8 threshold:            he decided threshold for this specific
*                                 password storage
*
*     const uint8 *secret:        the secret data provided to scramble the
*                                 shamir secret share instance
* 
*     unsigned int secret_length: the length of the secret to use, should be 
*                                 less than SHARE_LENGTH by preference
*
*      uint8 partial_bytes:       in case partial verification wants to be 
*                                 disabled, a 0 will do
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type:   pph_context         the resulting context or NULL if something 
*                                 fails
* PROCESS :
*     TODO: THIS
*
* CHANGES :
*     TODO: 
*/
pph_context* pph_init_context(uint8 threshold, const uint8* secret,
                              unsigned int secret_length, uint8 partial_bytes);


/*******************************************************************
* NAME :            pph_destroy_conext
*
* DESCRIPTION :     Destroy an existing instance of pph_context, securely 
*                   dstroying its resources.
*
* INPUTS :
*   PARAMETERS:
*     pph_context *context: the context to destroy
*
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type:   PPH_ERROR     
*                    value:                     when:
*                   PPH_ERROR_OK                  the free process worked
*
*                   PPH_ERROR_UNKNOWN             if something weird happens    
* PROCESS :
*     Basically destroy pointers in the structure and then free the structure
*     itself, doing sanity checks in between child and parent structure 
*     destruction. 
*
* CHANGES :
*     First revision, won't delete accounts perfectly
*/
PPH_ERROR pph_destroy_context(pph_context *context);
                             


/*******************************************************************
* NAME :            pph_create_account
*
* DESCRIPTION :     given a context and some other data, create a user
*                   entry in the polypasshashcontext with the desired 
*                   information.
*
* INPUTS :
*   PARAMETERS:
*     pph_context *ctx:      This is the context in which the account wiil be 
*                            created
*     
*     const uint8 *username: This is the desired username for the new entry
*
*     const uint8 *password: This is the password for the new entry
*
*     uint8 shares:          This is the shares we decide to allocate to this
*                            new account. 
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type: int PPH_ERROR     
*           Values:        When:
*           TODO: THIS              
*           
* PROCESS :
*     TODO: THIS
*
* CHANGES :
*     TODO: 
*/
PPH_ERROR pph_create_account(pph_context *ctx, const uint8 *username,
                        const uint8 *password, uint8 shares);


/*******************************************************************
* NAME :          pph_check_log_in  
*
* DESCRIPTION :   Check whether a username and password combination exists 
*                 inside the loaded PPH context
*
* INPUTS :
*   PARAMETERS:
*     pph_context *ctx:     The context in which we are working
*
*     const char *username: The username attempt
*
*     const char *password: The password attempt
*
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type: int PPH_ERROR     
*           Values:                         When:
*           PPH_ACCOUNT_IS_INVALID            The combination does not exist
*           
*           PPH_USERNAME_IS_TOO_LONG          The username/pw won't fit in the
*                                             context anyway
*
*           PPH_BAD_PTR                       When pointers are null or out
*                                             of range
*
*           PPH_ERROR_UNKNOWN                 anytime else
*           
* PROCESS :
*     TODO: THIS
*
* CHANGES :
*     TODO: 
*/
PPH_ERROR pph_check_log_in(pph_context *ctx, const char *username, 
                                                const char *password);


/*******************************************************************
* NAME :          pph_unlock_password_data 
*
* DESCRIPTION :   given a context and pairs of usernames and passwords,
*                 unlock the password secret. 
*
* INPUTS :
*   PARAMETERS:
*     pph_context *ctx:      The context in which we are working
*
*     uint8 share_number:    The length of the username/password pair arrays
*
*     const char *usernames: The username attempts
*
*     const char *passwords: The password attempts
*
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type: int PPH_ERROR     
*           Values:                         When:
*           PPH_ACCOUNT_IS_INVALID            We couln't recombine with the 
*                                             information given
*           
*           PPH_USERNAME_IS_TOO_LONG          The username/pw won't fit in the
*                                             context anyway
*
*           PPH_BAD_PTR                       When pointers are null or out
*                                             of range
*
*           PPH_ERROR_UNKNOWN                 anytime else
*           
* PROCESS :
*     TODO: THIS
*
* CHANGES :
*     TODO: 
*/
PPH_ERROR pph_unlock_password_data(pph_context *ctx, uint8 share_number,
                          const uint8 *usernames[], const uint8 *passwords[]);
                                  


/* inline functions */
// These are most possibly private helpers that aid in readibility 
// with the api functions
inline void _xor_share_with_digest(uint8 *result, uint8 *share,
     uint8 * digest,unsigned int length){
  int i;
  unsigned int *xor_digest_pointer;
  unsigned int *xor_share_pointer;
  unsigned int *xor_result_pointer;
  // xor the whole thing, we do this in an unsigned int fashion imagining 
  // this is where usually where the processor aligns things and is, hence
  // faster
  xor_digest_pointer = (unsigned int*)digest;
  xor_share_pointer = (unsigned int*)share;
  xor_result_pointer = (unsigned int*)result;
  
  for(i=0;i<length/sizeof(*xor_result_pointer);i++){
      *(xor_result_pointer + i) = 
        *(xor_share_pointer+i)^*(xor_digest_pointer +i);
  }
  return;
}

// we will make an inline of the hash calculation, since it is done in many
// places and looks too messy
inline void _calculate_digest(uint8 *digest, const uint8 *password){
  EVP_MD_CTX mctx;

  EVP_MD_CTX_init(&mctx);
  EVP_DigestInit_ex(&mctx, EVP_sha256(), NULL); //todo, we should make this
                                                // configurable through a
                                                // autoconf flag/define
  EVP_DigestUpdate(&mctx, password, strlen(password));
  EVP_DigestFinal_ex(&mctx,  digest, 0);
  EVP_MD_CTX_cleanup(&mctx);

}
#endif /* LIBPOLYPASSHASH_H */

