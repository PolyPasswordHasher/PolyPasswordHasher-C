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

  if(partial_bytes > DIGEST_LENGTH){
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

  // for the time being, the AES_key is the secret now. 
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
*     3) Allocate a share/digest entry for the account
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
  uint8 salt_buffer[SALT_LENGTH];
  uint8 salted_password[SALT_LENGTH+PASSWORD_LENGTH];

  
  // 1) SANITIZE INFORMATION
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

  // This while loop will traverse our accounts and check if the username is 
  // already taken.
  next = ctx->account_data;
  while(next!=NULL){
    node=next;
    next=next->next;
    if(username_length==node->account.username_length && // if the lengths match
        !memcmp(node->account.username,username,username_length)){//compare them
      return PPH_ACCOUNT_IS_INVALID; 
    }
  }


  // 2) check for the type of account requested.
  
  // this will generate a share list for non-thresholdless acounts, we won't 
  // fall inside this loop for thresholdless acounts since shares is 0.
  last_entry = NULL;
  for(i=0;i<shares;i++){
    // 3) Allocate entries for each account
 
    // get a new share value
    gfshare_ctx_enc_getshare( ctx->share_context, ctx->next_entry,
        share_data);


    // get a salt for the password
    get_random_salt(SALT_LENGTH, salt_buffer);

    // Try to get a new entry.
    entry_node=create_polyhashed_entry(password, password_length, salt_buffer,
        SALT_LENGTH, share_data, SHARE_LENGTH, ctx->partial_bytes);
    if(entry_node == NULL){
      _destroy_entry_list(last_entry);
      return PPH_NO_MEM;
    }
    
    // update the share number for this entry, and update the next available
    // share in a round robin fashion
    entry_node->share_number = ctx->next_entry;
    ctx->next_entry++;
    if(ctx->next_entry==0 || ctx->next_entry>=MAX_NUMBER_OF_SHARES){
      ctx->next_entry=1;
    }   

    // add the node to the list
    entry_node->next = last_entry;
    last_entry=entry_node;
  }
  // This if will check for thresholdless accounts, and will build a single 
  // entry for them.
  if(shares == 0){
    // 3) allocate an entry for each account
 
    // get a salt for the password
    get_random_salt(SALT_LENGTH, salt_buffer); 
 
    // generate the entry
    entry_node = create_thresholdless_entry(password, password_length,
        salt_buffer, SALT_LENGTH, ctx->AES_key, DIGEST_LENGTH,
        ctx->partial_bytes);

    if(entry_node == NULL){
      return PPH_NO_MEM;
    }
    // we now have one share entry under this list, so we increment this
    // parameter.
    shares++;
  }
  
  // 4) Allocate the information for the account
  // allocate the account information, check for memory issues and return.
  node=malloc(sizeof(*node));
  if(node==NULL){
    // we should destroy the list we created now to avoid memory leaks
    _destroy_entry_list(entry_node);
    return PPH_NO_MEM;
  }

  // fill with the user entry with the rest of the account information.
  memcpy(node->account.username,username,username_length);
  node->account.number_of_entries = shares;
  node->account.username_length = username_length;
  node->account.entries = entry_node;

  // 5) add the resulting account to the current context.

  // append it to the context list, with the rest of thee users
  node->next = ctx->account_data;
  ctx->account_data = node;

  // 6) return.
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
  pph_account_node *search; // this will be used to iterate all the users 

  pph_account_node *target = NULL; // this will, ideally, point to target 
                                   //   username, if he exists in the list
  
  uint8 share_data[SHARE_LENGTH];  // this is a buffer to store the current 
                                   //  share
  
  uint8 resulting_hash[DIGEST_LENGTH]; // this will hold our calculated hash
  
  uint8 salted_password[SALT_LENGTH+PASSWORD_LENGTH]; // this is the buffer
                                                      // we will use for hashing
  
  uint8 xored_hash[SHARE_LENGTH];
  uint8 sharenumber;

  pph_entry *current_entry;

  unsigned int i;
  unsigned int partial_bytes_offset; // this will hold an offset value for 
                                     // partial verification.
  // openSSL managers.
  EVP_CIPHER_CTX de_ctx;
  int p_len,f_len;


  // 1) Sanitize data and return errors.
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

  // 2) Try to find the user in our context.
  // search for our user, we search the entries with the same username length 
  // first, and then we check if the contents are the same. 
  search = ctx->account_data;
  while(search!=NULL){
    if(username_length == search->account.username_length && // check lengths
        !memcmp(search->account.username,username,username_length)){// compare
      target = search;
    }
    search=search->next;
  } 

  if(target == NULL){ //i.e. we found no one
    return PPH_ACCOUNT_IS_INVALID;
  }

  // if we reach here, we should have enough resources to provide a login
  // functionality to the user.
  
  // 3) We found it, try to verify the proper password for him.
  // first, check what type of account is this
  if(target->account.entries == NULL){
    return PPH_ERROR_UNKNOWN; // this probably happens if data is inconsistent
  }

  // we get the first entry to check if this is a valid login, we could be 
  // thorough and check for each, but it looks like an overkill
  current_entry = target->account.entries;
  sharenumber = current_entry->share_number;
  partial_bytes_offset = DIGEST_LENGTH - ctx->partial_bytes;
  // if the context is not unlocked, we can only provide partial verification  
  if(ctx->is_unlocked != 1){
    // partial bytes check
    // calculate the proposed digest, this means, calculate the hash with
    // the information just provided about the user. 
    memcpy(salted_password,current_entry->salt,current_entry->salt_length);
    memcpy(salted_password+current_entry->salt_length, password,
        current_entry->password_length);; 
    _calculate_digest(resulting_hash, salted_password, 
       current_entry->salt_length + password_length);
   
    // only compare the bytes that are not obscured by either AES or the 
    // share, we start from share_length-partial_bytes to share_length. 
    if(memcmp(resulting_hash+partial_bytes_offset,
          target->account.entries->polyhashed_value+partial_bytes_offset,
          ctx->partial_bytes)){
      return PPH_ACCOUNT_IS_INVALID;
    }
    return PPH_ERROR_OK;
  }

  // we are unlocked and hence we can provide full verification.
  else{ 
    // first, check if the account is a threshold or thresholdless account.
    if(sharenumber == 0){
      // if the sharenumber is 0 then we have a thresholdless account
      if(ctx->AES_key != NULL && ctx->is_unlocked == 1){ // extra safety check
        // now we should calculate the expected hash by decyphering the
        // information inside the context.
        EVP_CIPHER_CTX_init(&de_ctx);
        EVP_DecryptInit_ex(&de_ctx, EVP_aes_256_ctr(), NULL, ctx->AES_key, NULL);
        EVP_DecryptUpdate(&de_ctx, xored_hash, &p_len, 
            current_entry->polyhashed_value, partial_bytes_offset);
        EVP_DecryptFinal_ex(&de_ctx, xored_hash+p_len, &f_len);
        EVP_CIPHER_CTX_cleanup(&de_ctx);

        // append the unencrypted bytes if we have partial bytes. 
        for(i=p_len+f_len;i<DIGEST_LENGTH;i++){
          xored_hash[i] = current_entry->polyhashed_value[i]; //
        }

        // calculate the proposed digest with the parameters provided in
        // this function.
        memcpy(salted_password,current_entry->salt, current_entry->salt_length);
        memcpy(salted_password+current_entry->salt_length, password, 
            password_length); 
        _calculate_digest(resulting_hash, salted_password, 
            current_entry->salt_length + password_length);

        
        // 3) compare both, and they should match.
        if(memcmp(resulting_hash, xored_hash, DIGEST_LENGTH)){
          return PPH_ACCOUNT_IS_INVALID;
        }
        return PPH_ERROR_OK;
      }
      return PPH_ACCOUNT_IS_INVALID;
    }
    
    // we have a non thresholdless account instead, since the sharenumber is 
    // not 0
    else{
      // we do it the normal way for this. We have a valid sharenumber
      // get the share
      gfshare_ctx_enc_getshare(ctx->share_context, sharenumber, share_data);

      // calculate the proposed digest with the salt from the account and
      // the password in the argument.
      memcpy(salted_password,current_entry->salt, current_entry->salt_length);
      memcpy(salted_password+current_entry->salt_length, password, 
          password_length); 
      _calculate_digest(resulting_hash, salted_password, 
          current_entry->salt_length + password_length);
      
      // xor the thing back to normal
      _xor_share_with_digest(xored_hash,current_entry->polyhashed_value,
          share_data, partial_bytes_offset);
      // append the unobscured bytes
      for(i=DIGEST_LENGTH-ctx->partial_bytes;i<DIGEST_LENGTH;i++){
        xored_hash[i] = target->account.entries->polyhashed_value[i]; //
      }
      // compare both.
      if(memcmp(resulting_hash, xored_hash, DIGEST_LENGTH)){
        return PPH_ACCOUNT_IS_INVALID;
      }
      return PPH_ERROR_OK; // this means, the login does match
    } 
  }
  // if we get to reach here, we where diverged from usual flow. 
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
    // check if each of our users is inside the context.
    for(i = 0; i<username_count;i++){
  
      if(!memcmp(usernames[i],current_user->account.username,
            current_user->account.username_length)){
        // this is an existing user
        entry = current_user->account.entries;
        
        // check if he is a threshold account.
        if(entry->share_number != 0){
          // if he is a threshold account, we must attempt to reconstruct the
          // shares using his information. 
          while(entry!=NULL){

            // calulate the digest given his password.
            memcpy(salted_password,entry->salt,entry->salt_length);
            memcpy(salted_password+entry->salt_length, passwords[i],
                entry->password_length);
            _calculate_digest(estimated_digest,salted_password,
                SALT_LENGTH + current_user->account.entries->password_length);

            // xor the obtained digest with the polyhashed value to obtain
            // our share.
            _xor_share_with_digest(estimated_share,entry->polyhashed_value,
                estimated_digest,SHARE_LENGTH-ctx->partial_bytes);
         
            // give share to the recombinator. 
            share_numbers[entry->share_number] = entry->share_number+1;
            gfshare_ctx_dec_giveshare(G, entry->share_number,estimated_share);

            // move to the next entry.
            entry = entry->next;
          }
        } 
      }
    } 
    current_user = current_user->next;
  }

  // now we attempt to recombine the secret, we have given him all of the 
  // obtained shares.
  gfshare_ctx_dec_newshares(G, share_numbers);

  // if the secret is not initialized, allocate some memory for it and copy
  // the obtained secret.
  if(ctx->secret == NULL){
    gfshare_ctx_dec_extract(G, secret);
    ctx->secret = calloc(sizeof(ctx->secret),SHARE_LENGTH-ctx->partial_bytes);
    memcpy(ctx->secret,secret,SHARE_LENGTH-ctx->partial_bytes);
  }else{ // if it isn't, copy the share directly to the existing buffer.
    gfshare_ctx_dec_extract(G,ctx->secret);
  }
  // if the share context is not initialized, intialize one with the information
  // we have about our context. 
  if(ctx->share_context == NULL){
    for(i=0;i<MAX_NUMBER_OF_SHARES;i++){
      share_numbers[i]=(unsigned char)i+1;
    }
    ctx->share_context = gfshare_ctx_init_enc( share_numbers,
                                               MAX_NUMBER_OF_SHARES-1,
                                               ctx->threshold,
                                               SHARE_LENGTH-ctx->partial_bytes);
  }
  
  // we have an initialized share context, we set the recombined secret to it 
  // and set the unlock flag to one so it is ready to use.
  gfshare_ctx_enc_setsecret(ctx->share_context, ctx->secret);
  ctx->is_unlocked = 1;
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
*     1) Sanitize the data (unset flags, point secret to NULL)
*     2) open the selected file.
*     3) traverse the dynamic linked lists storing everything
*     4) close the file, return appropriate error
*
* CHANGES :
*     None as of this version
*/
PPH_ERROR pph_store_context(pph_context *ctx, const unsigned char *filename){
  FILE *fp;
  pph_account_node *current_node;
  pph_context context_to_store; // we use a hard copy so we can mess with it
                                // without damaging the one from the user, he
                                // might want to keep using it and we need
                                // to set some values before writing. 
  pph_entry *current_entry;  


  // 1) sanitize the data
  if(ctx == NULL || filename == NULL){
    return PPH_BAD_PTR;
  }
  
  // we backup the context so we can mess with it without breaking anything. 
  memcpy(&context_to_store,ctx,sizeof(*ctx));

  // NULL out the pointers, we won't store that, not even where it used to point
  context_to_store.share_context = NULL;
  context_to_store.AES_key = NULL;
  context_to_store.secret = NULL;
  context_to_store.account_data = NULL;

  // set this context's information to locked.
  context_to_store.is_unlocked = 0; 

  // 2) open selected file
  fp=fopen(filename,"wb");
  if(fp==NULL){
    return PPH_FILE_ERR;
  }

  // 3) write the context
  fwrite(&context_to_store,sizeof(context_to_store),1,fp); 

  // traverse the list and write it too.
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


  // 4) close the file, return appropriate error
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
*     1) Sanitize the data (check the string is a good string) 
*     2) open the selected file.
*     3) Build a dynamic list by traversing the file's contents
*     4) close the file, return appropriate structure
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

  // 1) sanitize data
  if(filename == NULL){
    return NULL;
  }

  // 2) open selected file
  fp= fopen(filename,"rb");
  if(fp == NULL){
    return NULL;
  }
  
  // 3) load the context structure from the file. 
  loaded_context = malloc(sizeof(*loaded_context));
  if(loaded_context == NULL){
    return NULL;
  }
  fread(loaded_context,sizeof(*loaded_context),1,fp);
  
  // build the account and entry list out of the information from the file. 
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
  
  // 4) close the file.
  fclose(fp);
  return loaded_context;
}






// helper functions ///////////////////////

// this generates a random secret of the form [stream][streamhash], the 
// parameters are the length of each section of the secret
uint8 *generate_pph_secret(unsigned int stream_length,
    unsigned int hash_bytes){
  return NULL;
}

// this checks whether a given secret complies with the pph_secret prototype
// ([stream][streamhash])
PPH_ERROR check_pph_secret(uint8 *secret, unsigned int stream_length, 
    unsigned int hash_bytes){
  return PPH_ERROR_UNKNOWN;
}






// this function provides a polyhashed entry given the input
pph_entry *create_polyhashed_entry(uint8 *password, unsigned int
    password_length, uint8 *salt, unsigned int salt_length, uint8 *share,
    unsigned int share_length, unsigned int partial_bytes){


  pph_entry *entry_node = NULL;
  
  // we hold a buffer for the salted password.
  uint8 salted_password[SALT_LENGTH+PASSWORD_LENGTH]; 

  // check input pointers are correct
  if(password == NULL || salt == NULL || share == NULL){
    return NULL;
  }

  // check for valid lengths
  if(password_length > PASSWORD_LENGTH || salt_length > SALT_LENGTH){
    return NULL;
  }

  // check for valid lengths on the share information
  if(share_length > SHARE_LENGTH || partial_bytes > SHARE_LENGTH){
    return NULL;
  }

  entry_node = malloc(sizeof(*entry_node));
  if(entry_node==NULL){
    return NULL;
  }

  // update the salt value in the entry
  memcpy(entry_node->salt,salt, salt_length);
  entry_node->salt_length = salt_length;
  entry_node->password_length = password_length;

  // prepend the salt to the password
  memcpy(salted_password,salt,salt_length);
  memcpy(salted_password+salt_length, password, password_length);

  // hash the salted password
  _calculate_digest(entry_node->polyhashed_value, salted_password,
        salt_length + password_length);
    
  // xor the whole thing, with the share, we are doing operations in-place
  // to make everything faste
  _xor_share_with_digest(entry_node->polyhashed_value, share,
        entry_node->polyhashed_value, share_length-partial_bytes);
    
  return entry_node;
}


// this other function is the equivalent to the one in the top, but for
// thresholdless accounts.
pph_entry *create_thresholdless_entry(uint8 *password, unsigned int
    password_length, uint8* salt, unsigned int salt_length, uint8* AES_key,
    unsigned int key_length, unsigned int partial_bytes){


  pph_entry *entry_node = NULL;
  uint8 salted_password[SALT_LENGTH + PASSWORD_LENGTH];

  // openssl encryption contexts
  EVP_CIPHER_CTX en_ctx;
  int c_len,f_len;



  // check everything makes sense, nothing should point to null
  if(password == NULL || salt == NULL || AES_key == NULL){
    return NULL;
  }

  // check for password and pass lengths
  if(password_length > PASSWORD_LENGTH || salt_length > SALT_LENGTH){
    return NULL;
  }

  // we check that the key is shorter than the digest we are using for
  // ctr mode, but we could ommit this, partial bytes should be shorter
  // than the digest length since we cannot reveal more bytes than the ones
  // we have.
  if(key_length > DIGEST_LENGTH || partial_bytes > DIGEST_LENGTH){
    return NULL;
  }

  // allocate memory and fail if there is not memory available.
  entry_node = malloc(sizeof(*entry_node));
  if(entry_node==NULL){
    return NULL;
  }

  // copy the salt into the pph_entry
  memcpy(entry_node->salt, salt, salt_length);
  entry_node->salt_length = salt_length;
  
  // prepend the salt to the password and generate a digest
  memcpy(salted_password,entry_node->salt,salt_length);
  memcpy(salted_password+SALT_LENGTH, password, password_length); 
  _calculate_digest(entry_node->polyhashed_value,salted_password, 
      salt_length + password_length); 

  // encrypt the generated digest
  EVP_CIPHER_CTX_init(&en_ctx);
  EVP_EncryptInit_ex(&en_ctx, EVP_aes_256_ctr(), NULL, AES_key, NULL);
  EVP_EncryptUpdate(&en_ctx, entry_node->polyhashed_value, &c_len,
      entry_node->polyhashed_value, DIGEST_LENGTH-partial_bytes);
  EVP_EncryptFinal_ex(&en_ctx, entry_node->polyhashed_value+c_len, &f_len);
  EVP_CIPHER_CTX_cleanup(&en_ctx);


  // thresholdless accounts have this value defaulted to 0;
  entry_node->share_number = 0;

  // thresholdless accounts should have only one entry
  entry_node->next = NULL;

  return entry_node;  

}



// This is a private helper that produces a salt string,
void get_random_salt(unsigned int length, uint8 *dest){
  unsigned int i;
  FILE *fp;

  fp = fopen("/dev/urandom","rb");
  fread(dest,sizeof(uint8),length,fp);
  fclose(fp);
}


