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
  context->secret = malloc(sizeof(uint8)*secret_length+1);
  if(context->secret == NULL){
    free(context);
    return NULL;
  }
  memcpy(context->secret,secret,sizeof(uint8)*secret_length);
  context->secret[secret_length]='\0';
  for(i=0;i<MAX_NUMBER_OF_SHARES;i++){
    share_numbers[i]=(unsigned char)i+1;
  }
  context->share_context = NULL;
  context->share_context = gfshare_ctx_init_enc( share_numbers,
                                                 MAX_NUMBER_OF_SHARES-1,
                                                 context->threshold,
                                                 SHARE_LENGTH);
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
  context->next_entry=1;
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
      // free their entry list
      _destroy_entry_list(current->account.entries);
      free(current); 
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
  
  pph_account_node *node,*next;
  unsigned int length;
  unsigned int i;
  pph_entry *entry_node,*last_entry;
  uint8 current_entry;
  uint8 share_data[SHARE_LENGTH];
  uint8 resulting_hash[DIGEST_LENGTH];
  uint8 salted_password[SALT_LENGTH+PASSWORD_LENGTH];
  // SANITIZE INFORMATION
  //
  // check password length
  length = strlen(password);
  if(length > PASSWORD_LENGTH-1){
    return PPH_PASSWORD_IS_TOO_LONG;
  }
  // check username length
  length = strlen(username);
  if(length > USERNAME_LENGTH-1){
    return PPH_USERNAME_IS_TOO_LONG;
  }
  // check share numbers
  if(shares>MAX_NUMBER_OF_SHARES){// we do not check for 0 because of the 
                                  // the thresholdless accounts
    return PPH_WRONG_SHARE_COUNT;
  }
  // check correct context pointer
  if(ctx == NULL){
    return PPH_BAD_PTR;
  }

  // check if we are able to get shares from the context vault
  if(ctx->is_unlocked != 1){
    return PPH_CONTEXT_IS_LOCKED;
  }

  // check non-existing username
  next = ctx->account_data;
  while(next!=NULL){
    node=next;
    next=next->next;
    if(!strcmp(node->account.username,username)){
      return PPH_ACCOUNT_IS_INVALID;
    }
  }

  last_entry = NULL;
  for(i=0;i<shares;i++){
    entry_node=malloc(sizeof(*entry_node));
    if(entry_node==NULL){
      // destroy the list we had to far... it's a shame if you ask me ...
      _destroy_entry_list(entry_node);
      return PPH_NO_MEM;
    }
    // get a share number
    entry_node->share_number = ctx->next_entry;
    ctx->next_entry++;
    if(ctx->next_entry==0){
      ctx->next_entry++;
    }

    // get a new share.
    gfshare_ctx_enc_getshare( ctx->share_context, entry_node->share_number,
        share_data);
   // get a salt for this entry, we are using sprintf, but we could use 
    // memcpy in case this function requires it.
    get_random_salt(SALT_LENGTH, entry_node->salt);
    entry_node->salt[SALT_LENGTH-1]='\0';
    sprintf(salted_password,"%s%s",entry_node->salt, password);
 
    _calculate_digest(resulting_hash, salted_password);
    
    // xor the whole thing, we do this in an unsigned int fashion imagining 
    // this is where usually where the processor aligns things and is, hence
    // faster
    _xor_share_with_digest(entry_node->hashed_value, share_data,
        resulting_hash, DIGEST_LENGTH);
    
    // add the node to the list
    entry_node->next = last_entry;
    last_entry=entry_node;
  }

  // allocate the account information 
  node=malloc(sizeof(*node));
  if(node==NULL){
    // we should destroy the list we created now...
    _destroy_entry_list(entry_node);
    return PPH_NO_MEM;
  }
  // fill username information
  strncpy(node->account.username,username,USERNAME_LENGTH);
  node->account.number_of_entries = shares;
  node->account.entries = entry_node; 

  // append it to the context list.
  node->next = ctx->account_data;
  ctx->account_data = node;

  // everything is set! 
  return PPH_ERROR_OK;
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
PPH_ERROR pph_check_login(pph_context *ctx, const char *username, 
                                                const char *password){
  pph_account_node *target = NULL; // this will, ideally, point to target 
                                   //   username
  uint8 share_data[SHARE_LENGTH];  // this is a buffer to store the current 
                                   //  share
  uint8 resulting_hash[DIGEST_LENGTH]; // this will hold our calculated hash
  uint8 salted_password[SALT_LENGTH+PASSWORD_LENGTH]; // this is the buffer
                                                      // we will use for hashing
  uint8 xored_hash[SHARE_LENGTH];
  uint8 sharenumber;
  unsigned int i;

  pph_account_node *search; // this will be used to iterate all the users 
  // check for any improper pointers
  if(ctx == NULL || username == NULL || password == NULL){
    return PPH_BAD_PTR;
  }

  // if the length is too long for either field, return proper error, we
  // are substracting the null character as it is not included in the check
  if(strlen(username) > USERNAME_LENGTH-1){
    return PPH_USERNAME_IS_TOO_LONG;
  }
  
  // do the same for the password
  if(strlen(password) > PASSWORD_LENGTH-1){
    return PPH_PASSWORD_IS_TOO_LONG;
  }

  // check if the context is locked and we lack partial bytes to check
  if(ctx->is_unlocked != 1 && ctx->partial_bytes == 0){
    return PPH_CONTEXT_IS_LOCKED;
  }

  // search for our user
  search = ctx->account_data;
  while(search!=NULL){
    if(!strncmp(search->account.username,username,USERNAME_LENGTH)){
      target = search;
    }
    search=search->next;
  } 
  if(target == NULL){ //i.e. we found no one
    return PPH_ACCOUNT_IS_INVALID;
  }

  // if we reach here, we should have enough resources to provide a login
  // functionality to the user.
  
  // first, check what type of account is this
  // , for this, verify we can get a sharenumber out of this...
  if(target->account.entries == NULL){
    return PPH_ERROR_UNKNOWN; // this probably happens if data is inconsistent
  }
  sharenumber = target->account.entries->share_number;// we need only the first 
                                             // share to do the checking
  if(sharenumber == 0){ // non admin
    return PPH_ERROR_UNKNOWN; // TODO: do something instead of breaking
    // we should recheck if partial bytes are involved or use the AES key to 
    // decrypt the result. 
  }else{
    // we do it the normal way for this. We have a valid sharenumber
    //
    // get the share
    gfshare_ctx_enc_getshare(ctx->share_context, sharenumber, share_data);

    // calculate the proposed digest with the salt.
    sprintf(salted_password,"%s%s",target->account.entries->salt,password);
    _calculate_digest(resulting_hash, salted_password);
    
    // xor the thing back to normal
    _xor_share_with_digest(xored_hash,target->account.entries->hashed_value,
        share_data, DIGEST_LENGTH);

    // compare, TODO: optimize this.
    for(i=0;i<DIGEST_LENGTH;i++){
      if(xored_hash[i] != resulting_hash[i]){
        return PPH_ACCOUNT_IS_INVALID;
      } 
    }
    return PPH_ERROR_OK; // this means, the login does match
  } 

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
*     pph_context *ctx:             The context in which we are working
*
*     unsigned int username_count:  The length of the username/password pair 
*                                   arrays
*
*     const char *usernames:        The username attempts
*
*     const char *passwords:        The password attempts
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
*           PPH_ACCOUNT_IS_INVALID            We couldn't recombine with the 
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
PPH_ERROR pph_unlock_password_data(pph_context *ctx,unsigned int username_count,
                          const uint8 *usernames[], const uint8 *passwords[]){
  
  
  uint8 share_numbers[MAX_NUMBER_OF_SHARES];
  gfshare_ctx *G;
  unsigned int i;
  uint8 salted_password[USERNAME_LENGTH+SALT_LENGTH];
  uint8 estimated_digest[DIGEST_LENGTH];
  uint8 estimated_share[SHARE_LENGTH];
  pph_entry *entry;
  
  pph_account_node *current_user;
  
  //sanitize the data.
  if(ctx == NULL || usernames == NULL || passwords == NULL){
    return PPH_BAD_PTR;
  }

  if(username_count < ctx->threshold){
    return PPH_ACCOUNT_IS_INVALID;
  }

  // initialize the share numbers
  for(i=0;i<MAX_NUMBER_OF_SHARES;i++){
    share_numbers[i] = 0;
    //share_numbers[i] = (uint8)(i+1);
  }
  // do the reconstruction. 
  G = gfshare_ctx_init_dec( share_numbers, MAX_NUMBER_OF_SHARES-1,
     SHARE_LENGTH);

  // traverse our possible users
  current_user=ctx->account_data;
  while(current_user!=NULL){
    // check if our users lies inside this 
    // TODO: do this faster
    for(i = 0; i<username_count;i++){
      if(!strcmp(usernames[i],current_user->account.username)){
        // this is an existing user! 
        // give all of it's calculated shares to libgfshare...
        entry = current_user->account.entries;
        while(entry!=NULL){
          // calulate the share
          sprintf(salted_password,"%s%s",entry->salt,passwords[i]);
          _calculate_digest(estimated_digest,salted_password);
          _xor_share_with_digest(estimated_share,entry->hashed_value,
              estimated_digest,SHARE_LENGTH);
         
          // give share to recombine
          share_numbers[entry->share_number] = entry->share_number+1;
          gfshare_ctx_dec_giveshare(G, entry->share_number,estimated_share);

          entry = entry->next;
        } 
      }
    } 
    current_user = current_user->next;
  }
  gfshare_ctx_dec_newshares(G, share_numbers);
  gfshare_ctx_dec_extract(G, ctx->secret);
  gfshare_ctx_enc_setsecret(ctx->share_context, ctx->secret);
  return PPH_ERROR_UNKNOWN;
}


/*******************************************************************
* NAME :          pph_store_context
*
* DESCRIPTION :   store the information of the working context into a file. 
*                 The status of the secret is lost in the process and the 
*                 structure is set as such. After reloading the stucture, the
*                 user should call pph_unlock_password_data with enough 
*                 valid accounts.
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
*                                             succcessfully.
*
*           PPH_BAD_PTR                       When pointers are null or out
*                                             of range
*           
*           PPH_FILE_ERR                      when the file selected is non-
*                                             writable. 
*
*           PPH_ERROR_UNKNOWN                 anytime else
*           
* PROCESS :
*     * Sanitize the data (unset flags, point secret to NULL)
*     * open the selected file.
*     * traverse the dynamic linked lists storing everything
*     * close the fule, return appropriate error
*
* CHANGES :
*     None as of this version
*/
PPH_ERROR pph_store_context(pph_context *ctx, const unsigned char *filename){
  return PPH_ERROR_UNKNOWN;
}
 

/*******************************************************************
* NAME :          pph_reload_context
*
* DESCRIPTION :   Reload a pph_context stored in a file, the secret is
*                 unknown and the structure is locked by default.
*                 pph_unlock_password _data should be called after this returns
*                 a sucessfull pointer 
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
pph_context *pph_reload_context(const unsigned char *filename){
  return NULL;
}
 


// This produces a salt string,
void get_random_salt(unsigned int length, uint8 *dest){
  static uint8 seed_is_created = 0;
  unsigned int i;

  if(!seed_is_created){
    srand(time(NULL));
    seed_is_created = 1;
  }

  for(i=0;i<length;i++){
    // we do scaling for printable characters, this might not be the best idea
    // in the world.
    dest[i] = (rand()%95)+32;
  }
}


