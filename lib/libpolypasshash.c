/*
 * This file is Copyright Santiago Torres Arias <torresariass@gmail.com> 2014
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
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

#include "config.h"
#include "libgfshare.h"
#include "libpolypasshash.h"


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
*                                 shamir secret share instance. The resulting
*                                 structure won't make a copy of this.
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
                              unsigned int secret_length, uint8 partial_bytes){
  
  pph_context *context;
  unsigned char share_numbers[MAX_NUMBER_OF_SHARES];//this is a specific
                                                    //initialization constant.
  unsigned int i;
  //CHECK ARGUMENT SANITY
  // secret
  if(secret == NULL){
    return NULL;
  }
  // threshold
  if(threshold==0){
    return NULL;
  }
  // secret length
  if(secret_length == 0 || secret_length > PASSWORD_LENGTH){//TODO: do we need
                                                            // another constant
                                                            // ?
    return NULL;
  }

  if(partial_bytes > DIGEST_LENGTH){// TODO:should we evaluate for half of this
    return NULL;
  }

  //INITIALIZE DATA STRUCTURE
  // malloc
  context = malloc(sizeof(*context));
  if(context == NULL){
    return NULL;
  }// TODO: evaluate if we should check for sub-allocation

  // fill
  context->threshold=threshold;
  
  context->secret = NULL; //cue the paranoid parrot meme...
  context->secret = malloc(sizeof(uint8)*secret_length);
  if(context->secret == NULL){
    free(context);
    return NULL;
  }
  memcpy(context->secret,secret,sizeof(uint8)*secret_length);

  for(i=0;i<MAX_NUMBER_OF_SHARES;i++){
    share_numbers[i]=(unsigned char)i+1;
  }
  context->share_context = NULL;
  context->share_context = gfshare_ctx_init_enc( share_numbers,
                                                 MAX_NUMBER_OF_SHARES-1,
                                                 context->threshold,
                                                 MAX_NUMBER_OF_SHARES);
  if(context->share_context == NULL){
    free(context);
    return NULL;
  }
  gfshare_ctx_enc_setsecret(context->share_context, context->secret);
  
  context->available_shares = (uint8)MAX_NUMBER_OF_SHARES;

  context->is_unlocked = 1; 

  context->partial_bytes=partial_bytes;
  if(partial_bytes !=0){
    // should generate AES key
  }else{
    context->AES_key = NULL;
  }

  context->shares=NULL;
  context->account_data=NULL;

  return context;
}

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
*
*                   PPH_BAD_PTR                   if the pointer given is null
* PROCESS :
*     Basically destroy pointers in the structure and then free the structure
*     itself, doing sanity checks in between child and parent structure 
*     destruction. 
*
* CHANGES :
*     First revision, won't delete accounts. 
*/
PPH_ERROR pph_destroy_context(pph_context *context){
  // do the first check
  pph_account_node *current,*next;
  PPH_ERROR error = PPH_ERROR_UNKNOWN;
  if(context == NULL){
    return PPH_BAD_PTR;
  }
  
  // do child freeing.
  if(context->AES_key != NULL){ // this is probably unnecessary as per the spec
    free(context->AES_key);
  }

  if(context->secret !=NULL){
    free(context->secret);
  }

  if(context->shares !=NULL){
    free(context->shares);
  }

  if(context->account_data != NULL){
    next = context->account_data;
    while(next!=NULL){
      current=next;
      next=next->next;
      free(current); //TODO: this should work, but test it....
    }
  }

  gfshare_ctx_free(context->share_context);

  // now it is safe to free everything
  free(context);

  error = PPH_ERROR_OK;

  return error;
}


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
                        const uint8 *password, uint8 shares){
  EVP_MD_CTX mctx;
   
  return PPH_ERROR_UNKNOWN;
}


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
                                                const char *password){
  
  return PPH_ERROR_UNKNOWN;
}


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
                          const uint8 *usernames[], const uint8 *passwords[]){

  return PPH_ERROR_UNKNOWN;
}
 
#include <errno.h>
#include <stdlib.h>
#include <string.h>


