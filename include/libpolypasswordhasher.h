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
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdbool.h>


// constants declaration

// the length of our share buffers
#define SHARE_LENGTH 256/8              
#define DIGEST_LENGTH SHARE_LENGTH

// the maximum number of shares to use in this framework.
#define MAX_NUMBER_OF_SHARES 255

// these constants are set to meet the password hashing competition guidelines
#define MAX_USERNAME_LENGTH 128            
#define MAX_SALT_LENGTH 16                  
#define MAX_PASSWORD_LENGTH 128            

// the pph secret contains a specific signature to be able to discern from a 
// valid secret to an invalid one. This signature corresponds to the following
// layout: [random_bytes][hash_of_random_bytes]. We define here the length of
// the first and two sections of the secret.
#define SIGNATURE_HASH_BYTE_LENGTH 4
#define SIGNATURE_RANDOM_BYTE_LENGTH DIGEST_LENGTH-SIGNATURE_HASH_BYTE_LENGTH
#define SIGNATURE_HASH_ITERATIONS 10000 /* The number of iterations should be set higher */
#define ICB_HASH_ITERATIONS 10000

// Account type defines, for readability
#define SHIELDED_ACCOUNT 0
#define BOOTSTRAP_ACCOUNT -1



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
  PPH_ACCOUNT_EXISTS,
  PPH_WRONG_SHARE_COUNT,
  PPH_CONTEXT_IS_LOCKED,
  PPH_VALUE_OUT_OF_RANGE,
  PPH_SECRET_IS_INVALID,

  // system or user is being brilliant. 
  PPH_FILE_ERR,
  PPH_NO_MEM,
  PPH_BAD_PTR,

  // developer is not brilliant
  PPH_ERROR_UNKNOWN,

} PPH_ERROR;





/* structure definitions */

// this will help us keeping the code tidier, a pph_entry is a protector 
// value, it's associated sharenumber, the salt length and the salt for it. 
typedef struct _pph_entry{
  
  // the share number that belongs to this entry
  short share_number;

  // information about the salt  
  uint8 salt[MAX_SALT_LENGTH];      
  unsigned int salt_length;

  // information about the password, this is either the xored hash of the 
  // password or the encrypted hash of the password.
  uint8 sharexorhash[DIGEST_LENGTH];
  uint8 isolated_check_bits[DIGEST_LENGTH];

  struct _pph_entry *next;

} pph_entry;


// This holds information about a single username.
typedef struct _pph_account{

  // information about the username stream.
  unsigned char username[MAX_USERNAME_LENGTH]; 
  unsigned int username_length;

  // information about the entries associated with this username.
  uint8 number_of_entries;                 
  pph_entry *entries;                      

} pph_account;



// this is a helper structure to hold the user nodes. 
typedef struct _pph_account_node{ 

  struct _pph_account_node* next;
  pph_account account;

} pph_account_node;

// we will have a data structure for previous logins
typedef struct _pph_previous_login{
  
  pph_entry *entry;
  uint8 digest[DIGEST_LENGTH];
  struct _pph_previous_login *next;

} pph_previous_login;

// we will have a data structure for bootstrap entries to update them
// after bootstrapping.
typedef struct _pph_bootstrap_entry {

    pph_entry *entry;
    struct _pph_bootstrap_entry *next;
} pph_bootstrap_entry;


// The context structure defines all of what's needed to handle a polypasswordhasher
// store.
typedef struct _pph_context{
  
  // this share context manages the share generation and secret recombination
  gfshare_ctx *share_context;    
  uint8 threshold;               

  // This is the max number of available shares for this context. Next entry
  // will allocate the shares in a round-robin fashion.
  uint8 available_shares;        
  uint8 next_entry;             
 
  // this is a boolean flag to indicate if the secret is available.  
  bool is_normal_operation;             
  
  // if the context is under normal operation, these will point to the secret
  // and the AES key
  uint8 *AES_key;                
  uint8 *secret;
  uint8 secret_integrity[DIGEST_LENGTH]; /* we will store the whole integrity check now */

  // This is the number of isolated-check-bits associated with the context.
  // If isolated-check-bits is 0, isolated validation is disabled. 
  uint8 isolated_check_bits;           
  
  // this points to the account nodes currently available.  
  pph_account_node* account_data;

  // we will populate a list of previous logins to fully verify after 
  // bootstrapping
  pph_previous_login *previous_logins;

  // this will contain entries to be updated after bootstrapping.
  pph_bootstrap_entry *bootstrap_entries;

} pph_context;





/* Function Declarations */
/*******************************************************************
* NAME :            pph_init_context
*
* DESCRIPTION :     Initialize a poly pass hash structure with everything
*                   we need in order to work. The produced structure will
*
*                   This is the layout of the generated structure:
*
*                   typedef struct _pph_context{
*                     gfshare_ctx* share_context      = new share context
*                     uint8 threshold                 = threshold
*                     uint8 available_shares;         = MAX_NUMBER_OF_SHARES
*                     uint8 next_entry;               = 1
*                     bool is_normal_operation;       = true   
*                     uint8 *AES_key;                 = will point to secret       
*                     uint8 *secret;                  = generated secret
*                     uint8 isolated_check_bits;            = isolated_check_bits
*                     pph_account_node* account_data; = NULL
*                   } pph_context;
*                
*
* INPUTS :
*   PARAMETERS:
*     uint8 threshold:            The threshold for this 
*                                 password storage. This is, the minimum
*                                 number of shares needed to transition to
*                                 normal operation upon reloading. The valid
*                                 ranges for the threshold go from 1 to
*                                 MAX_NUMBER_OF_SHARES;
*                                 however, a value of 1 is a bad idea.
*
*     uint8 isolated_check_bits:  The number of hashed-bytes to leak in order 
*                                 to perform isolated validation. If 
*                                 isolated_check_bits = 0, isolated validation
*                                 is disabled. isolated-check-bits should range
*                                 from 0 to DIGEST_LENGTH, but a value from 0 to
*                                 4 is recommended.
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type:   pph_context         the resulting context or NULL when either 
*                                 allocation fails or the input given is not
*                                 within the valid ranges.
* PROCESS :
*   1) verify arguments
*   2) allocate data structures
*   3) generate a custom random secret
*   4) initialize the rest of the values
*   5) initialize the secret generator.
*   7) return 
*
* CHANGES :
*     21/04/2014: secret is no longer a parameter
*/

pph_context* pph_init_context(uint8 threshold, uint8 isolated_check_bits);





/*******************************************************************
* NAME :            pph_destroy_context
*
* DESCRIPTION :     Destroy an existing instance of pph_context, securely 
*                   destroying its resources.
*
*                   The structure will have to free the following elements 
*                   before it can be safely freed:
*
*                   typedef struct _pph_context{
*                     gfshare_ctx* share_context      = needs freeing
*                     uint8 threshold                 = 
*                     uint8 available_shares;         = 
*                     uint8 next_entry;               = 
*                     bool is_normal_operation;       = 
*                     uint8 *AES_key;                 = needs freeing      
*                     uint8 *secret;                  = needs freeing
*                     uint8 isolated_check_bits;            = 
*                     pph_account_node* account_data; = needs freeing
*                   } pph_context;

*
* INPUTS :
*   PARAMETERS:
*     pph_context *context: the context to destroy
*
* OUTPUTS :
*   PARAMETERS:
*     pph_context *context: the context to free/destroy.    
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type:   PPH_ERROR     
*                    value:                     when:
*                   PPH_ERROR_OK                  the free process worked
*
*                   PPH_BAD_PTR                   if the pointer given is NULL
*
* PROCESS :
*     Basically destroy pointers in the structure and then free the structure
*     itself, doing sanity checks in between child and parent structure 
*     destruction. 
*
* CHANGES :
*     (03/17/14): Account freeing is done now. 
*/

PPH_ERROR pph_destroy_context(pph_context *context);
                             




/*******************************************************************
* NAME :            pph_create_account
*
* DESCRIPTION :     given a context and some other data, create a user
*                   entry in the polypasswordhasher context with the desired 
*                   information.
*
* INPUTS :
*   PARAMETERS:
*     pph_context *ctx:                   This is the context in which the
*                                         account will be created
*     
*     uint8 *username:                    This is the desired username for the
*                                         new entry
*
*     unsigned int username_length:       The length of the username field,
*                                         this value should not exceed 
*                                         MAX_USERNAME_LENGTH.
*
*     uint8 *password:                    This is the password for the new entry
*
*     unsgned int password_length:        The length of the password field, this
*                                         value should not exceed 
*                                         MAX_PASSWORD_LENGTH
*
*     uint8 shares:                       This is the amount of shares we decide 
*                                         to allocate to this new account. 
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type: int PPH_ERROR     
*           Values:                       When:
*             PPH_ERROR_OK                 The credentials provided are correct
*             
*             PPH_BAD_PTR                  One of the fields is unallocated
*
*             PPH_ERROR_UNKNOWN            When something unexpected happens.
*
*             PPH_NO_MEM                   If malloc, calloc fails.
*
*             PPH_USERNAME_IS_TOO_LONG     When the value for username_length 
*                                          is too long.
*
*             PPH_PASSWORD_IS_TOO_LONG     when the value for password_length
*                                          is too long
*
*             PPH_CONTEXT_IS_LOCKED        When the context is locked and, hence
*                                          he cannot create accounts
*
*             PPH_ACCOUNT_IS_INVALID       If the username provided already 
*                                          exists
*
* PROCESS :
*     1) Check for data sanity, and return errors
*     2) Check the type of account requested
*     3) Allocate a share/digest entry for the account
*     4) Initialize the account data with the information provided
*     5) Update the context information regarding the new account
*     6) return
*
* CHANGES :
*   Added support for different length accounts
*/

PPH_ERROR pph_create_account(pph_context *ctx, const uint8 *username,
                        unsigned int username_length, uint8 *password, 
                        unsigned int password_length, uint8 shares);






/*******************************************************************
* NAME :          pph_check_login  
*
* DESCRIPTION :   Check whether a username and password combination exists 
*                 inside the loaded PPH context.
*
* INPUTS :
*   PARAMETERS:
*     pph_context *ctx:     The context in which we are working
*
*     const char *username: The username attempt
*
*     unsigned int username_length: The length of the username field
*
*     const char *password: The password attempt
*
*     unsigned int password_length: the length of the password field
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
*           PPH_USERNAME_IS_TOO_LONG          The username won't fit in the 
*                                             buffer
*
*           PPH_PASSWORD_IS_TOO_LONG          The password won't fit in the 
*                                             buffer associated to it. 
*
*           PPH_BAD_PTR                       When pointers are null or out
*                                             of range
*
*           PPH_ERROR_UNKNOWN                 any time else
*           
* PROCESS :
*     1) Sanitize data and return errors
*     2) try to find username in the context
*     3) if found, decide how to verify his information based on the status
*         of the context (shielded, isolated validation, etc.)
*     4) Do the corresponding check and return the proper error
*
* CHANGES :
*  (21/04/2014): Added support for non-null-terminated usernames and passwords.
*/

PPH_ERROR pph_check_login(pph_context *ctx, const char *username, 
                          unsigned int username_length, uint8 *password,
                          unsigned int password_length);





/*******************************************************************
* NAME :          pph_unlock_password_data 
*
* DESCRIPTION :   given a context and pairs of usernames and passwords,
*                 unlock the password secret. 
*
* INPUTS :
*   PARAMETERS:
*     pph_context *ctx:                The context in which we are working
*
*     unsigned int username_count:     The length of the username/password arrays
*
*     const char *usernames:           The username attempts
*
*     unsigned int username_lengths[]: The length of the username fields, 
*                                      in the same order as the usernames.
*
*     const char *passwords:           The password attempts
*
* OUTPUTS :
*   PARAMETERS:
*     type: pph_context             The context provided will be activated and
*                                   pointed to the secret if combination was 
*                                   successful
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type: int PPH_ERROR     
*           Values:                         When:
*           PPH_ACCOUNT_IS_INVALID            We couldn't recombine with the 
*                                             information given
*           
*           PPH_USERNAME_IS_TOO_LONG          The username won't fit in the
*                                             buffer allocated to it.
*
*           PPH_PASSOWRD_IS_TOO_LONG          The password won't fit in it's
*                                             assigned buffer
*
*           PPH_BAD_PTR                       When pointers are null or out
*                                             of range
*
*           PPH_ERROR_UNKNOWN                 any time else
*           
* PROCESS :
*     1) Verify input sanity
*     2) traverse user accounts searching for proposed username
*     3) produce shares out of the password digest
*     4) give shares to the recombination context
*     5) attempt recombination
*     6) verify correct recombination.
*     7) if successful, transition from bootstrapping to normal operation.
*     8) return error code
*
* CHANGES :
*     (03/25/14): Secret consistency check was added. 
*/

PPH_ERROR pph_unlock_password_data(pph_context *ctx,
        unsigned int username_count, const uint8 *usernames[], 
        unsigned int username_lengths[], const uint8 *passwords[],
        unsigned int password_lengths[]);
                                  




/*******************************************************************
* NAME :          pph_store_context
*
* DESCRIPTION :   store the information of the working context into a file. 
*                 Elements as the secret and the share context are not stored.
*                 
*
* INPUTS :
*   PARAMETERS:
*     pph_context *ctx:              The context in which we are working
*
*     const unsigned char* filename: The filename of the datastore to use
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
*           PPH_ERROR_OK                      When the file was stored 
*                                             successfully.
*
*           PPH_BAD_PTR                       When pointers are null or out
*                                             of range
*           
*           PPH_FILE_ERR                      when the file selected is non-
*                                             writable. 
*
*           PPH_ERROR_UNKNOWN                 any time else
*           
* PROCESS :
*     * Sanitize the data (unset flags, point secret to NULL)
*     * open the selected file.
*     * traverse the dynamic linked lists storing everything
*     * close the file, return appropriate error
*
* CHANGES :
*     None as of this version
*/

PPH_ERROR pph_store_context(pph_context *ctx, const unsigned char *filename);
                                  




/*******************************************************************
* NAME :          pph_reload_context
*
* DESCRIPTION :   Reload a pph_context stored in a file, the secret is
*                 unknown and the structure is locked by default.
*                 pph_unlock_password_data should be called after this returns
*                 a valid pointer 
*
* INPUTS :
*   PARAMETERS:
*     const unsigned char* filename: The filename of the datastore to use
*
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type: pph_context * 
*
*           Values:                         When:
*            NULL                             The file is not loadable
*                                             or data looks corrupted
*           
*            A valid pointer                  if everything went fine
* 
* PROCESS :
*     * Sanitize the data (check the string is a good string) 
*     * open the selected file.
*     * Build a dynamic list by traversing the file's contents
*     * close the file, return appropriate structure
*
* CHANGES :
*     None as of this version
*/

pph_context *pph_reload_context(const unsigned char *filename);
 




/*******************************************************************
* NAME :          PHS 
*
* DESCRIPTION :   Generate a password hash, given the password, and salt. 
*                 This is a "virtual" interface and functions as a proof of
*                 context for the password hashing competition. A context will
*                 be initialized upon calling, and will be destroyed upon
*                 return. No persistent setup is done in this function, and no
*                 accounts are created. 
*
* INPUTS :
*   PARAMETERS:
*     void *out:          The resulting hash buffer. The resulting hash will be
*                         copied here. 
*
*     size_t outlen:      The size of the hash to produce, this version only
*                         supports 32 byte-length outputs. 
*
*     const void *in:     The input password to hash.
*
*     size_t inlen:       The length of the input, the maximum supported length
*                         is 128.
*
*     const void *salt:   The salt to use with the password
*
*     size_t saltlen:     The length of the salt to use. The maximum supported
*                         length is 16
*
*     int tcost:          Time cost for this function. This parameter 
*                         translates directly to the threshold of the
*                         generated context. With a bigger threshold, the time
*                         to initialize a context rises. This value can't be 0.
*
*     int mcost:          Memory cost (unusable this time)
*
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type: int
*
*           Values:                         When:
*            0                                On error ok. 
*
*            !=0                              In case of error.
* 
* PROCESS 
*     1) verify the input. 
*     2) Generate a pph_context if there is none in memory
*     3) Generate a protector entry
*     4) Copy the protector value to the output buffer
*     5) Return.
*
* CHANGES :
*     None as of this version
*/

int PHS(void *out, size_t outlen, const void *in, size_t inlen,
   const void* salt, size_t saltlen, int tcost, int mcost); 

									 										 

// helper functions //////////////////////////



// used to generate a random secret and add its hash
uint8 *generate_pph_secret( uint8 *integrity_check);



// this checks whether a given secret matches the given integrity check (stored
// in the context) at certain number of iterations
PPH_ERROR check_pph_secret(uint8 *secret, uint8 *secret_integrity);


// this function provides a protector entry given the input
pph_entry *create_protector_entry(uint8 *password, unsigned int
    password_length, uint8 *salt, unsigned int salt_length, const void *share,
    unsigned int share_length, unsigned int isolated_check_bits);




// this other function is the equivalent to the one in the top, but for
// shielded accounts.
pph_entry *create_shielded_entry(uint8 *password, unsigned int
    password_length, uint8* salt, unsigned int salt_length, uint8* AES_key,
    unsigned int key_length, unsigned int isolated_check_bits);

// Finally, this function, creates an entry for an account that was created during
// bootstrapping.
pph_entry *create_bootstrap_entry(uint8 *password, unsigned int password_length, 
        uint8 *salt, unsigned int salt_length);



/* inline functions */

// These are most possibly private helpers that aid in readability 
// with the API functions.

// xoring two streams of bytes. 
inline void _xor_share_with_digest(uint8 *result, uint8 *share,
     uint8 * digest,unsigned int length) {
  int i;
  unsigned int *xor_digest_pointer;
  unsigned int *xor_share_pointer;
  unsigned int *xor_result_pointer;
  int aligned_length = length/sizeof(*xor_result_pointer);
  int char_aligned_length = aligned_length * sizeof(*xor_result_pointer);
  int char_aligned_offset = length%sizeof(*xor_result_pointer);

  // xor the whole thing, we do this in an unsigned int fashion imagining 
  // this is where usually where the processor aligns things and is, hence
  // faster
  xor_digest_pointer = (unsigned int*)digest;
  xor_share_pointer = (unsigned int*)share;
  xor_result_pointer = (unsigned int*)result;
  
  for(i=0;i<aligned_length;i++) {
      *(xor_result_pointer + i) = 
        *(xor_share_pointer+i)^*(xor_digest_pointer +i);
  }
  
  // xor the rest, if we have a number that's not divisible by a word.
  for(i = char_aligned_length; i<char_aligned_length+char_aligned_offset;i++) {
    *(result+i) = *(share+i) ^ *(digest+i); 
  }
    
  return;
    
}



// we will make an inline of the hash calculation, since it is done in many
// places and looks too messy
inline void _calculate_digest(uint8 *digest, const uint8 *password,
    unsigned int length) {
  EVP_MD_CTX mctx;

  EVP_MD_CTX_init(&mctx);
  EVP_DigestInit_ex(&mctx, EVP_sha256(), NULL); 
                                               
                                              
  EVP_DigestUpdate(&mctx, password, length);
  EVP_DigestFinal_ex(&mctx,  digest, 0);
  EVP_MD_CTX_cleanup(&mctx);

  return;

}

// we will use an inline to encrypt a digest to make everything cleaner also
//Add an additional input which is the IV that will be used by the CTR mode ~GA
inline void _encrypt_digest(uint8 *result, uint8 *digest, uint8 *AES_key, uint8* iv) {

  EVP_CIPHER_CTX en_ctx;
  int c_len,f_len;

  // encrypt the generated digest
  EVP_CIPHER_CTX_init(&en_ctx);
  EVP_EncryptInit_ex(&en_ctx, EVP_aes_256_ctr(), NULL, AES_key, iv);
  EVP_EncryptUpdate(&en_ctx, result, &c_len,
      digest, DIGEST_LENGTH);
  EVP_EncryptFinal_ex(&en_ctx, result+c_len, &f_len);
  EVP_CIPHER_CTX_cleanup(&en_ctx);

  return;


}



// in the generate user event and when destroying a context object
inline void _destroy_entry_list(pph_entry *head) {
  pph_entry *last;
  last=head;
  while(head!=NULL) {
    head=head->next;
    free(last);
    last=head;
  }

  return;

} 
#endif /* LIBPOLYPASSHASH_H */

