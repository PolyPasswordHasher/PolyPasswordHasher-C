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
*      uint8 partial_bytes:       The number of hashed-bytes to leak in order to
*                                 perform partial verification. In case partial
*                                 verification wants to be disabled, set to 0.
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
*   1) verify parameters are well formed
*   2) allocate data structures
*   3) generate a custom random secret
*   4) initialize the rest of the values
*   5) initialize the secret generator.
*   7) return 
*
* CHANGES :
*     21/04/2014: secret is no longer a parameter
*/
pph_context* pph_init_context(uint8 threshold, uint8 partial_bytes){

  pph_context *context;
  unsigned char share_numbers[MAX_NUMBER_OF_SHARES];//this is a specific
                                                    //initialization constant.
  unsigned int i;
  // 1) CHECK ARGUMENT SANITY
  // threshold
  if(threshold==0){
    return NULL;
  }

  if(partial_bytes > DIGEST_LENGTH){// TODO:should we evaluate for half of this
    return NULL;
  }

  // 2)INITIALIZE DATA STRUCTURE
  
  context = malloc(sizeof(*context));
  if(context == NULL){
    return NULL;
  }// TODO: evaluate if we should check for sub-allocation

  // fill
  context->threshold=threshold;
  
  // initialize the partial bytes offset, this will be used to limit the
  // length of the shares, and the length of the digest to xor/encrypt
  context->partial_bytes=partial_bytes;

  // 3) generate random secret! 
  context->secret = NULL; //cue the paranoid parrot meme...
  context->secret = malloc(sizeof(context->secret)*SHARE_LENGTH-partial_bytes);
  if(context->secret == NULL){
    free(context);
    return NULL;
  }
  get_random_salt(SHARE_LENGTH-partial_bytes, context->secret);
  // 4) Initialize the rest of the values
  context->available_shares = (uint8)MAX_NUMBER_OF_SHARES;

  // since this is a new context, it should be unlocked
  context->is_unlocked = 1; 

  // FIXME, the AES key should be, actually, the secret. 
  //context->AES_key = generate_AES_key_from_context(context, DIGEST_LENGTH); 
  context->AES_key = context->secret;

  // initialize the rest
  context->next_entry=1;
  context->account_data=NULL;



  // 5) Initialize share context
  for(i=0;i<MAX_NUMBER_OF_SHARES;i++){
    share_numbers[i]=(unsigned char)i+1;
  }

  // Update the share context, the size of the shares is reduced by the number
  // or partial bytes.
  context->share_context = NULL;
  context->share_context = gfshare_ctx_init_enc( share_numbers,
                                                 MAX_NUMBER_OF_SHARES-1,
                                                 context->threshold,
                                                 SHARE_LENGTH-partial_bytes);
  if(context->share_context == NULL){
    free(context->secret);
    free(context);
    return NULL;
  }
  gfshare_ctx_enc_setsecret(context->share_context, context->secret);
  
  // finish, return our product
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
  //if(context->AES_key != NULL){ // this is probably unnecessary as per the spec
    //free(context->AES_key);
  //}

  if(context->secret !=NULL){
    free(context->secret);
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
  if(context->share_context!=NULL){
    gfshare_ctx_free(context->share_context);
  }
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
*     pph_context *ctx:                   This is the context in which the
*                                         account wiil be created
*     
*     const uint8 *username:              This is the desired username for the
*                                         new entry
*
*     const unsigned int username_length: the length of the username field,
*                                         this value should not exceed 
*                                         USERNAME_LENGTH.
*
*     const uint8 *password:              This is the password for the new entry
*
*     const unsgned int password_length:  The length of the password field, this
*                                         value should not exceed 
*                                         PASSWORD_LENGTH
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
*             PPH_USERNAME_IS_TOO_LONG     When that happens
*
*             PPH_PASSWORD_IS_TOO_LONG     The same thing
*
*             PPH_CONTEXT_IS_LOCKED        When the context is locked and, hence
*                                          he cannot create accounts
*
*             PPH_ACCOUNT_IS_INVALID       If the username provided already 
*                                          exists
*
*
* PROCESS :
*     1) Check for data sanity, and return errors
*     2) Check the type of account requested
*     3) Allocate a share/digest entry for the accound
*     4) Initialize the account data with the information provided
*     5) Update the context information regarding the new account
*     6) return
*
* CHANGES :
*   Added support for different length accounts
*/
PPH_ERROR pph_create_account(pph_context *ctx, const uint8 *username,
                        const unsigned int username_length, 
                        const uint8 *password, 
                        const unsigned int password_length, uint8 shares){
  pph_account_node *node,*next;
  unsigned int length;
  unsigned int i;
  pph_entry *entry_node,*last_entry;
  uint8 current_entry;
  uint8 share_data[SHARE_LENGTH];
  uint8 resulting_hash[DIGEST_LENGTH];
  uint8 salted_password[SALT_LENGTH+PASSWORD_LENGTH];
  // openssl encryption contexts
  EVP_CIPHER_CTX en_ctx;
  size_t c_len,f_len;
  
  // 1) SANITIZE INFORMATION
  //
  // check password length
  if(password_length > PASSWORD_LENGTH-1){
    return PPH_PASSWORD_IS_TOO_LONG;
  }
  // check username length
  if(username_length > USERNAME_LENGTH-1){
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
  if(ctx->is_unlocked != 1 || ctx->AES_key == NULL){
    return PPH_CONTEXT_IS_LOCKED;
  }

  // check non-existing username
  next = ctx->account_data;
  while(next!=NULL){
    node=next;
    next=next->next;
    if(!memcmp(node->account.username,username,username_length)){
      return PPH_ACCOUNT_IS_INVALID;
    }
  }

  last_entry = NULL;
  for(i=0;i<shares;i++){
    entry_node=malloc(sizeof(*entry_node));
    if(entry_node==NULL){
      // destroy the list we had to far... it's a shame if you ask me ...
      _destroy_entry_list(entry_node); //FIXME: this will not work...
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
    memcpy(salted_password,entry_node->salt,SALT_LENGTH);
    memcpy(salted_password+SALT_LENGTH, password, password_length);
    //sprintf(salted_password,"%s%s",entry_node->salt, password);
    _calculate_digest(entry_node->hashed_value, salted_password,
        SALT_LENGTH + password_length);
    
    // xor the whole thing, we do this in an unsigned int fashion imagining 
    // this is where usually where the processor aligns things and is, hence
    // faster
    _xor_share_with_digest(entry_node->hashed_value, share_data,
        entry_node->hashed_value, DIGEST_LENGTH-ctx->partial_bytes);
    
    // add the node to the list
    entry_node->next = last_entry;
    last_entry=entry_node;
  }
  if(shares == 0){
    // i.e this is a thresholdless account. 
    entry_node = malloc(sizeof(*entry_node));
    if(entry_node==NULL){
      return PPH_NO_MEM;
    }
    entry_node->share_number = 0;
    
    // generate the digest
    get_random_salt(SALT_LENGTH, entry_node->salt);
    memcpy(salted_password,entry_node->salt,SALT_LENGTH);
    memcpy(salted_password+SALT_LENGTH, password, password_length); //FIXME: use a pw length parameter
    //sprintf(salted_password,"%s%s",entry_node->salt,password);
    _calculate_digest(resulting_hash,salted_password, 
        SALT_LENGTH + password_length); 

    // encrypt the digest
    EVP_CIPHER_CTX_init(&en_ctx);
    EVP_EncryptInit_ex(&en_ctx, EVP_aes_256_ctr(), NULL, ctx->AES_key, NULL);
    EVP_EncryptUpdate(&en_ctx, entry_node->hashed_value, &c_len, resulting_hash, 
      DIGEST_LENGTH-ctx->partial_bytes);
    /* update ciphertext with the final remaining bytes */
    EVP_EncryptFinal_ex(&en_ctx, entry_node->hashed_value+c_len, &f_len);
    EVP_CIPHER_CTX_cleanup(&en_ctx);

    // append the unencrypted bytes
    for(i=c_len+f_len;i<DIGEST_LENGTH;i++){
      entry_node->hashed_value[i] = resulting_hash[i]; //
    }

    //
    entry_node->next=NULL;
    shares++;


  }

  // allocate the account information 
  node=malloc(sizeof(*node));
  if(node==NULL){
    // we should destroy the list we created now...
    _destroy_entry_list(entry_node);
    return PPH_NO_MEM;
  }
  // fill username information
  memcpy(node->account.username,username,username_length);
  node->account.number_of_entries = shares;
  node->account.username_length = username_length;
  node->account.password_length = password_length;
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
*           PPH_USERNAME_IS_TOO_LONG          The username/pw won't fit in the
*                                             context anyway
*
*           PPH_BAD_PTR                       When pointers are null or out
*                                             of range
*
*           PPH_ERROR_UNKNOWN                 anytime else
*           
* PROCESS :
*     1) Sanitize data and return errors
*     2) try to find username in the context
*     3) if found, decide how to verify his information based on the status
*         of the context (thresholdless, partial verif, etc.)
*     4) Do the corresponding check and return the proper error
*
* CHANGES :
*  (21/04/2014): Added support for non-null-terminated usernames and passwords.
*/
PPH_ERROR pph_check_login(pph_context *ctx, const char *username, 
                          unsigned int username_length, const char *password,
                          unsigned int password_length){

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
  // openSSL managers.
  EVP_CIPHER_CTX de_ctx;
  size_t p_len,f_len;

  pph_account_node *search; // this will be used to iterate all the users 
  // check for any improper pointers
  if(ctx == NULL || username == NULL || password == NULL){
    return PPH_BAD_PTR;
  }

  // if the length is too long for either field, return proper error, we
  // are substracting the null character as it is not included in the check
  if(username_length > USERNAME_LENGTH-1){
    return PPH_USERNAME_IS_TOO_LONG;
  }
  
  // do the same for the password
  if(password_length > PASSWORD_LENGTH-1){
    return PPH_PASSWORD_IS_TOO_LONG;
  }

  // check if the context is locked and we lack partial bytes to check
  if(ctx->is_unlocked != 1 && ctx->partial_bytes == 0){
    return PPH_CONTEXT_IS_LOCKED;
  }

  // search for our user
  search = ctx->account_data;
  while(search!=NULL){
    if(!memcmp(search->account.username,username,username_length)){
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
  if(ctx->is_unlocked != 1){
   // partial bytes check
   // we should:
   // 1) calculate the proposed digest
   memcpy(salted_password,target->account.entries->salt,SALT_LENGTH);
   memcpy(salted_password+SALT_LENGTH, password,
       target->account.password_length); 
   // sprintf(salted_password,"%s%s",target->account.entries->salt,password);
   _calculate_digest(resulting_hash, salted_password, 
       SALT_LENGTH + password_length);
   
   // 2) only compare the bytes that are not obscured.
   for(i=DIGEST_LENGTH-ctx->partial_bytes;i<DIGEST_LENGTH;i++){
    if(resulting_hash[i]!=target->account.entries->hashed_value[i]){
      return PPH_ACCOUNT_IS_INVALID;
    }
   }
   return PPH_ERROR_OK;
  }
  else{ 
    if(sharenumber == 0){ // thresholdless case.
      if(ctx->AES_key != NULL && ctx->is_unlocked == 1){
        // we should:
        //
        // 1) calculate the expected hash...
        EVP_CIPHER_CTX_init(&de_ctx);
        EVP_DecryptInit_ex(&de_ctx, EVP_aes_256_ctr(), NULL, ctx->AES_key, NULL);
        EVP_DecryptUpdate(&de_ctx, xored_hash, &p_len,
            target->account.entries->hashed_value,
            DIGEST_LENGTH-ctx->partial_bytes);
        EVP_DecryptFinal_ex(&de_ctx, xored_hash+p_len, &f_len);
        EVP_CIPHER_CTX_cleanup(&de_ctx);
        // append the unencrypted bytes
        for(i=p_len+f_len;i<DIGEST_LENGTH;i++){
          xored_hash[i] = target->account.entries->hashed_value[i]; //
        }



        // 2) calculate the proposed digest with the salt.
        //sprintf(salted_password,"%s%s",target->account.entries->salt,password);
        memcpy(salted_password,target->account.entries->salt,SALT_LENGTH);
        memcpy(salted_password+SALT_LENGTH, password, password_length); 
        
        _calculate_digest(resulting_hash, salted_password, 
            SALT_LENGTH + password_length);

        
        // 3) compare the hashes....
        for(i=0;i<DIGEST_LENGTH;i++){// we check the whole hash, we don't expect
          // partial bytes to modify the end result
          if(resulting_hash[i]!=xored_hash[i]){
            return PPH_ACCOUNT_IS_INVALID;    
          }
        }

        return PPH_ERROR_OK;
      }

      return PPH_ACCOUNT_IS_INVALID;
    }else{
      // we do it the normal way for this. We have a valid sharenumber
      //
      // get the share
      gfshare_ctx_enc_getshare(ctx->share_context, sharenumber, share_data);

      // calculate the proposed digest with the salt.
      //sprintf(salted_password,"%s%s",target->account.entries->salt,password);
      memcpy(salted_password,target->account.entries->salt,SALT_LENGTH);
      memcpy(salted_password+SALT_LENGTH, password, password_length); 
      _calculate_digest(resulting_hash, salted_password, 
          SALT_LENGTH + password_length);

      // xor the thing back to normal
      _xor_share_with_digest(xored_hash,target->account.entries->hashed_value,
          share_data, DIGEST_LENGTH-ctx->partial_bytes);
      // append the unobscured bytes
      for(i=DIGEST_LENGTH-ctx->partial_bytes;i<DIGEST_LENGTH;i++){
        xored_hash[i] = target->account.entries->hashed_value[i]; //
      }


      // compare, TODO: optimize this.
      for(i=0;i<DIGEST_LENGTH;i++){
        if(xored_hash[i] != resulting_hash[i]){
          return PPH_ACCOUNT_IS_INVALID;
        } 
      }
      return PPH_ERROR_OK; // this means, the login does match
    } 
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
  uint8 secret[SHARE_LENGTH];
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
     SHARE_LENGTH-ctx->partial_bytes);

  // traverse our possible users
  current_user=ctx->account_data;
  while(current_user!=NULL){
    // check if our users lies inside this 
    // TODO: do this faster
    for(i = 0; i<username_count;i++){
      if(!memcmp(usernames[i],current_user->account.username,
            current_user->account.username_length)){
        // this is an existing user and counts towards the threshold
        // give all of it's calculated shares to libgfshare...
        entry = current_user->account.entries;
        if(!entry->share_number == 0){
          while(entry!=NULL){
            // calulate the share
            memcpy(salted_password,entry->salt,SALT_LENGTH);
            memcpy(salted_password+SALT_LENGTH, passwords[i],
                current_user->account.password_length);
            //sprintf(salted_password,"%s%s",entry->salt,passwords[i]);
            _calculate_digest(estimated_digest,salted_password,
                SALT_LENGTH + current_user->account.password_length);
            _xor_share_with_digest(estimated_share,entry->hashed_value,
                estimated_digest,SHARE_LENGTH-ctx->partial_bytes);
         
            // give share to recombine
            share_numbers[entry->share_number] = entry->share_number+1;
            gfshare_ctx_dec_giveshare(G, entry->share_number,estimated_share);

            entry = entry->next;
          }
        } 
      }
    } 
    current_user = current_user->next;
  }
  gfshare_ctx_dec_newshares(G, share_numbers);
  if(ctx->secret == NULL){
    gfshare_ctx_dec_extract(G, secret);
    ctx->secret = calloc(sizeof(ctx->secret),SHARE_LENGTH-ctx->partial_bytes);
    memcpy(ctx->secret,secret,SHARE_LENGTH-ctx->partial_bytes);
  }else{
    gfshare_ctx_dec_extract(G,ctx->secret);
  }
  if(ctx->share_context == NULL){
    for(i=0;i<MAX_NUMBER_OF_SHARES;i++){
      share_numbers[i]=(unsigned char)i+1;
    }
    ctx->share_context = gfshare_ctx_init_enc( share_numbers,
                                               MAX_NUMBER_OF_SHARES-1,
                                               ctx->threshold,
                                               SHARE_LENGTH-ctx->partial_bytes);
  }
  gfshare_ctx_enc_setsecret(ctx->share_context, ctx->secret);
  ctx->is_unlocked = 1;
  //ctx->AES_key = generate_AES_key_from_context(ctx, DIGEST_LENGTH);
  //
  ctx->AES_key = ctx->secret;
  return PPH_ERROR_OK;
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
*     * close the file, return appropriate error
*
* CHANGES :
*     None as of this version
*/
PPH_ERROR pph_store_context(pph_context *ctx, const unsigned char *filename){
  FILE *fp;
  pph_account_node *current_node;
  pph_context context_to_store; // we use a hard copy so we can mess with it
                                // without damaging the one from the user
  pph_entry *current_entry;  


  // sanitize the data
  if(ctx == NULL || filename == NULL){
    return PPH_BAD_PTR;
  }
  // open selected file
  fp=fopen(filename,"wb");
  if(fp==NULL){
    return PPH_FILE_ERR;
  }
  
  // persist the context first...
  memcpy(&context_to_store,ctx,sizeof(*ctx));
  // NULL out the pointers, we won't store that, not even the reference....
  context_to_store.share_context = NULL;
  context_to_store.AES_key = NULL;
  context_to_store.secret = NULL;
  context_to_store.account_data = NULL;
  context_to_store.is_unlocked = 0; // by default, this is locked upon storage
  fwrite(&context_to_store,sizeof(context_to_store),1,fp); 

  // traverse the list
  current_node = ctx->account_data;
  while(current_node!=NULL){
    // write current node...
    fwrite(current_node,sizeof(*current_node),1,fp);
    current_entry = current_node->account.entries;
    while(current_entry != NULL){
      fwrite(current_entry,sizeof(*current_entry),1,fp);
      current_entry = current_entry->next;
    }
    current_node = current_node->next;
  }
  // close the file, return appropriate error

  fclose(fp);
  return PPH_ERROR_OK;
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

  FILE *fp;
  pph_context *loaded_context;
  pph_account_node *accounts,*last,account_buffer;
  pph_entry *entries, *last_entry, entry_buffer;
  unsigned int i;

  // sanitize data
  if(filename == NULL){
    return NULL;
  }

  // open selected file
  fp= fopen(filename,"rb");
  if(fp == NULL){
    return NULL;
  }
  loaded_context = malloc(sizeof(*loaded_context));
  
  
  if(loaded_context == NULL){
    return NULL;
  }
  fread(loaded_context,sizeof(*loaded_context),1,fp);
  
  accounts = NULL;
  while(fread(&account_buffer,sizeof(account_buffer),1,fp) != 0){
    last = accounts;
    accounts = malloc(sizeof(account_buffer));
    memcpy(accounts,&account_buffer,sizeof(account_buffer));
    last_entry = NULL;
    for(i=0;i<account_buffer.account.number_of_entries;i++){
      entries = malloc(sizeof(*entries));
      fread(entries,sizeof(*entries),1,fp);
      entries->next = last_entry;
      last_entry = entries;
    }
    accounts->account.entries = entries;
    accounts->next = last;
    last = accounts; 
  }
  loaded_context->account_data = accounts;
  fclose(fp);
  return loaded_context;
}
 
// this produces an AES key of the desired length when given a share context.
uint8 *generate_AES_key_from_context(pph_context *ctx, unsigned int length){
  uint8 *generated_key;
  uint8 *share_buffer;
  unsigned int i;

  // better be safe
  if(ctx == NULL || ctx->share_context == NULL || ctx->is_unlocked == 0){
    return NULL;
  }

  // aloccate our buffers
  generated_key = calloc(sizeof(*generated_key),length);
  if(generated_key == NULL){
    return NULL;
  }
  share_buffer = calloc(sizeof(*share_buffer),length);
  if(share_buffer == NULL){
    free(generated_key);
    return NULL;
  }

  // traverse all the shares xoring each to produce an AES key...
  //for(i=0;i<MAX_NUMBER_OF_SHARES-1;i++){
  //  gfshare_ctx_enc_getshare(ctx->share_context, i, share_buffer);
  //  _xor_share_with_digest(generated_key, share_buffer, generated_key, length);
  //}
  EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, ctx->secret, 
      strlen(ctx->secret), 1, generated_key, NULL);
  return generated_key;
}

// This produces a salt string,
void get_random_salt(unsigned int length, uint8 *dest){
  unsigned int i;
  FILE *fp;

  fp = fopen("/dev/urandom","rb");
  fread(dest,sizeof(uint8),length,fp);
  fclose(fp);
}


