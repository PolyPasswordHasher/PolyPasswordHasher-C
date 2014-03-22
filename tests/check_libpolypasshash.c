/* Check shamir suite
 *
 * This suite is designed to test the functionalities of the libshamir
 * module. 
 *
 * @author  Santiago Torres
 * @date    10/03/2014
 * @license MIT
 */
#include<check.h>
#include"libgfshare.h"
#include"libpolypasshash.h"
#include<stdlib.h>
#include<strings.h>


// we test in the core functionality to avoid a threshold of 0, which
// is the only non possible value (everyting bigger would roll over)
// TODO: evaluate if using a uint8 for threshold is good enough. 
START_TEST(test_pph_init_context_wrong_threshold)
{ 
  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 0; // this is, obviously, the only wrong threshold value
                              
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          
  context = pph_init_context(threshold, partial_bytes);

  ck_assert_msg(context == NULL,
      "the context returned upon a wrong threshold value should be NULL");
  
}
END_TEST


START_TEST(test_pph_init_context_no_partial_bytes)
{
  // a placeholder for the result.
  pph_context *context;
  PPH_ERROR error;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          

  context = pph_init_context(threshold,partial_bytes);

  ck_assert_msg(context != NULL, "this was a good initialization");
  
  error = pph_destroy_context(context);

  ck_assert_msg(error == PPH_ERROR_OK, 
      "the free function didn't work properly");
}
END_TEST

// We intend to use it to check the correct parsing of the context values
START_TEST(test_create_account_context){
  PPH_ERROR error;

  // sending bogus information to the create user function.
  error = pph_create_account(NULL, "mr.user", strlen("mr.user"), 
      "yessir,verysecure", strlen("yessir,verysecure"), 1);
  
  ck_assert_msg(error == PPH_BAD_PTR, 
      "We should've gotten BAD_PTR in the return value");
  
}
END_TEST

// this test is intended to check correct sanity check on the username field
START_TEST(test_create_account_usernames){
  pph_context *context;
  PPH_ERROR error;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
  

  unsigned char username[USERNAME_LENGTH+1];
  unsigned int i;
  for(i=0;i<USERNAME_LENGTH;i++){
    username[i] = 'k'; // endless string
  }
  username[USERNAME_LENGTH] = '\0';

  // initialize a correct context from scratch
  context = pph_init_context(threshold,partial_bytes);
  
  // sending bogus information to the create user function.
  error = pph_create_account(context, username, strlen(username),
      "yessir,verysecure", strlen("yessir,verysecure"), 1);
  
  ck_assert_msg(error == PPH_USERNAME_IS_TOO_LONG, 
      "We should've gotten USERNAME_IS_TOO_LONG in the return value");
  // TODO: should check for existing usernames... in this test 
  error = pph_destroy_context(context);
  ck_assert_msg(error == PPH_ERROR_OK, 
      "the free function didn't work properly after failing to add a user");


}
END_TEST

// this test is intended to check correct sanity checks on the password fields
START_TEST(test_create_account_passwords){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned char password[PASSWORD_LENGTH+1];
  unsigned int i;
 
  context = pph_init_context(threshold, partial_bytes);

  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  
 for(i=0;i<PASSWORD_LENGTH;i++){
    password[i] = 'k'; // endless string of k's
  }
  password[PASSWORD_LENGTH] = '\0';
  // sending bogus information to the create user function.
  error = pph_create_account(context, "ichooseverylongpasswords",
      strlen("ichooseverylongpasswords"),password,strlen(password),1);
  
  ck_assert_msg(error == PPH_PASSWORD_IS_TOO_LONG, 
      "We should've gotten PPH_PASSWORD_IS_TOO_LONG in the return value");
  
  error = pph_destroy_context(context);

  ck_assert_msg(error == PPH_ERROR_OK, 
      "the free function didn't work properly");


}
END_TEST
// this test is intended to check the correct sanity check on the sharenumber
// field
START_TEST(test_create_account_sharenumbers){
  // as for this version, sharenumbers cannot be wrong due to the nature
  // of the sharenumber variable, but I will leave this test stated in case
  // this ever changes...
  }
END_TEST
// this test is intended to check that a correct account structure is 
// producted (i.e. hash, etc.)
START_TEST(test_create_account_entry_consistency){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned char password[] = "verysecure";
  unsigned char username[] = "atleastitry";
  unsigned char salted_password[] = {'x','x','x','x','x','x','x','x','x','x',
                                     'x','x','x','x','x','x','x','v','e','r',
                                     'y','s','e','c','u','r','e','\0'};
  // this is the calculated hash for the password without salt using 
  // an external tool
  uint8 password_digest[DIGEST_LENGTH]; 
                           
                          
                         
  unsigned int i;
  uint8 *digest_result;
  uint8 share_result[SHARE_LENGTH];

  context = pph_init_context(threshold, partial_bytes);

  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // sending bogus information to the create user function.
  error = pph_create_account(context, username,strlen(username),
      password,strlen(password),1);
  
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should've gotten PPH_ERROR_OK in the return value");
  
  context->account_data->account.username[strlen(username)]='\0'; // this makes
                                                                  // it easy
                                                                  // to cmp
  ck_assert_str_eq(username,context->account_data->account.username);

  // now lets check we can take the digest back from the death... I mean
  // share
  memcpy(salted_password,context->account_data->account.entries->salt,
      SALT_LENGTH);
  _calculate_digest(password_digest, salted_password, 
      SALT_LENGTH + strlen(password));
  digest_result=context->account_data->account.entries->hashed_value;

  gfshare_ctx_enc_getshare(context->share_context, 1, share_result);
  _xor_share_with_digest(digest_result, share_result, digest_result, 
      DIGEST_LENGTH);

  for(i=0;i<DIGEST_LENGTH;i++){
    ck_assert(password_digest[i]==digest_result[i]);
  }

  // we will check for the existing account error handler now...
  error = pph_create_account(context, username, strlen(username),
      password, strlen(password),1);

  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      "We should've gotten an error since this account repeats");
  
  // finally, check it returns the proper error code if the vault is locked
  // still
  context->is_unlocked = 0; // we simulate locking by setting the flag
                            // manually,
  
  // we will check for the existing account error handler now...
  error = pph_create_account(context, "someotherguy", strlen("someotherguy"),
    "came-here-asking-the-same-thing",strlen("came-here-asking-the-same-thing")
    ,1);

  ck_assert_msg(error == PPH_CONTEXT_IS_LOCKED, 
      "We should've gotten an error now that the vault is locked");
 
  error = pph_destroy_context(context);
  
  ck_assert_msg(error == PPH_ERROR_OK, 
      "the free function didn't work properly");



}
END_TEST

// this test is intended to check that the linked list is correctly created,
// checks for correct number of entries and username collisions
START_TEST(test_create_account_entry_list_consistency){
}
END_TEST

// This test checks for the input of the check_login function, proper error 
// codes should be returned. 
START_TEST(test_check_login_input_sanity){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned char password[] = "i'mnothere";
  unsigned char username[] = "nonexistentpassword";
  unsigned char too_big_username[USERNAME_LENGTH+1];
  unsigned char too_big_password[PASSWORD_LENGTH+1];
  unsigned int i;

  // lets send a null context pointer first
  context=NULL;
  error = pph_check_login(context, username,strlen(username), password,
      strlen(password));
  ck_assert_msg(error == PPH_BAD_PTR, "expected PPH_BAD_PTR");

  // we will send a wrong username pointer now
  context = pph_init_context(threshold, partial_bytes);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  error = pph_check_login(context, NULL, 0, password, 0);
  ck_assert_msg(error == PPH_BAD_PTR, "expected PPH_BAD_PTR");
 
  // do the same for the password 
  error = pph_check_login(context, username, 0, NULL, 0); 
  ck_assert_msg(error == PPH_BAD_PTR, "expected PPH_BAD_PTR");
  
  // now lets create some insanely big usernames and passwords
  for(i=0;i<USERNAME_LENGTH;i++){
    too_big_username[i]='j'; // endless stream of j's, just like bono
  }
  too_big_username[i]='\0'; // null terminate our string
  // and query for a login

  error = pph_check_login(context, too_big_username, strlen(too_big_username),
      password, strlen(password));
  ck_assert_msg(error == PPH_USERNAME_IS_TOO_LONG,
      "expected USERNAME_IS_TOO_LONG");

  // let's do the same with the password
  for(i=0;i<USERNAME_LENGTH;i++){
    too_big_password[i]='j'; // endless stream of j's
  }
  too_big_password[i]='\0'; // null terminate our string

  error=pph_check_login(context, username, strlen(username),
      too_big_password, strlen(too_big_password)); 
  ck_assert_msg(error == PPH_PASSWORD_IS_TOO_LONG,
      "expected PASSWORD_IS_TOO_LONG");
  
  // finally, check it returns the proper error code if the vault is locked
  // still
  context->is_unlocked = 0; // we simulate locking by setting the flag
                            // manually, remember, in this case
                            // partial bytes is also 0, that's why it must
                            // return such error.
  error=pph_check_login(context,username,strlen(username), password,
      strlen(password));
  ck_assert_msg(error == PPH_CONTEXT_IS_LOCKED,
     "expected CONTEXT_IS_LOCKED"); 
  
  pph_destroy_context(context);
}
END_TEST

// This checks for a proper return code when asking for the wrong username
START_TEST(test_check_login_wrong_username){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned char password[] = "i'mnothere";
  unsigned char username[] = "nonexistentpassword";
  unsigned char anotheruser[] = "0anotheruser";
  unsigned int i;

  // setup the context 
  context = pph_init_context(threshold,partial_bytes);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // check with an unitialized userlist first
  error = pph_check_login(context, username, strlen(username), password,
      strlen(password));
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      "expected ACCOUNT_IS_INVALID");

  // add a single user and see how it behaves:
  //
  // 1) add a user
  error = pph_create_account(context, anotheruser, strlen(anotheruser),
      "anotherpassword", strlen("anotherpassword"), 1);
  ck_assert_msg(error == PPH_ERROR_OK, " this shouldn't have broken the test");

  // 2) ask for a user that's not here
  error = pph_check_login(context, username, strlen(username), password,
      strlen(password));
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      "expected ACCOUNT_IS_INVALID");
  
  
  // lets add a whole bunch of users and check for an existing one again
  // 
  // 1) add a whole new bunch of users:
  for(i=1;i<9;i++){
    anotheruser[0] = i+48;
    error = pph_create_account(context, anotheruser, strlen(anotheruser),
        "anotherpassword",strlen("anotherpassword"), 1);
    ck_assert_msg(error == PPH_ERROR_OK,
        " this shouldn't have broken the test");
  }


  // 2) ask for a user that's not here
  error = pph_check_login(context, username, strlen(username), password,
      strlen(password));
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      "expected ACCOUNT_IS_INVALID");
  
  pph_destroy_context(context);
}
END_TEST


// This checks for a proper return code when providing a wrong password 
START_TEST(test_check_login_wrong_password){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned char password[] = "i'mnothere";
  unsigned char username[] = "nonexistentpassword";
  unsigned char anotheruser[] = "0anotheruser";
  unsigned int i;

  // setup the context 
  context = pph_init_context(threshold,partial_bytes);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  

  // add a single user and see how it behaves:
  // 1) add a user
  error = pph_create_account(context, username, strlen(username),
      "anotherpassword", strlen("anotherpassword"), 1);
  ck_assert_msg(error == PPH_ERROR_OK, " this shouldn't have broken the test");

  // 2) ask for it, providing wrong credentials
  error = pph_check_login(context, username, strlen(username), password, 
      strlen(password));
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      "expected ACCOUNT_IS_INVALID");
  
  
  // lets add a whole bunch of users and check for an existing one again
  // 1) add a whole new bunch of users:
  for(i=1;i<9;i++){
    anotheruser[0] = i+48;
    error = pph_create_account(context, anotheruser, strlen(anotheruser),
        "anotherpassword", strlen("anotherpassword"), 1);
    ck_assert_msg(error == PPH_ERROR_OK,
        " this shouldn't have broken the test");
  }


  // 2) ask again, with the wrong password
  error = pph_check_login(context, username, strlen(username), password,
      strlen(password));
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      "expected ACCOUNT_IS_INVALID");
  
  pph_destroy_context(context);
}
END_TEST

// This checks for a proper behavior when providing an existing username, 
// first, as the first and only username, then after having many on the list
START_TEST(test_check_login_proper_data){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned char password[] = "i'mnothere";
  unsigned char username[] = "nonexistentpassword";
  unsigned char anotheruser[] = "0anotheruser";
  unsigned int i;

  // setup the context 
  context = pph_init_context(threshold,partial_bytes);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  

  // add a single user and see how it behaves:
  // 1) add a user
  error = pph_create_account(context, username, strlen(username), password,
     strlen(password), 1);
  ck_assert_msg(error == PPH_ERROR_OK, " this shouldn't have broken the test");

  // 2) ask for it, providing correct credentials
  error = pph_check_login(context, username, strlen(username), password,
      strlen(password));
  ck_assert_msg(error == PPH_ERROR_OK, 
      "expected OK");
  
  
  // lets add a whole bunch of users and check for an existing one again
  // 1) add a whole new bunch of users:
  for(i=1;i<9;i++){
    anotheruser[0] = i+48;
    error = pph_create_account(context, anotheruser, strlen(anotheruser),
        "anotherpassword", strlen("anotherpassword"), 1);
    ck_assert_msg(error == PPH_ERROR_OK,
        " this shouldn't have broken the test");
  }


  // 2) ask again, with the wrong password
  error = pph_check_login(context, username, strlen(username), password,
      strlen(password));
  ck_assert_msg(error == PPH_ERROR_OK, 
      "expected ERROR_OK");
  
  pph_destroy_context(context);
}
END_TEST

// shamir recombination procedure test cases
START_TEST(test_pph_unlock_password_data_input_sanity){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned int i;
  unsigned int username_count=5;
  const uint8 *usernames[] = {"username1",
                              "username12",
                              "username1231",
                              "username26",
                              "username5",
                            };
  const uint8 *passwords[] = {"password1",
                              "password12",
                              "password1231",
                              "password26",
                              "password5"
                              };

  // check for bad pointers at first
  error = pph_unlock_password_data(NULL, username_count, usernames, passwords);
  ck_assert_msg(error == PPH_BAD_PTR," EXPECTED BAD_PTR");

  // setup the context 
  context = pph_init_context(threshold, partial_bytes);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // let's imagine it's all broken
  context->is_unlocked = 0;
  
  // now give a wrongusername count, i.e. below the threshold.
  error = pph_unlock_password_data(context, 0, usernames, passwords);
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      " Expected ACCOUNT_IS_INVALID");

  // do it again, more graphical... 
  error = pph_unlock_password_data(context, threshold -1, usernames, passwords);
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      " Expected ACCOUNT_IS_INVALID");

  // let's check for NULL pointers on the username and password fields
  error = pph_unlock_password_data(context, username_count, NULL, passwords);
  ck_assert_msg(error == PPH_BAD_PTR," EXPECTED BAD_PTR");

 
  // let's check for NULL pointers on the username and password fields
  error = pph_unlock_password_data(context, username_count, usernames, NULL);
  ck_assert_msg(error == PPH_BAD_PTR," EXPECTED BAD_PTR");

  pph_destroy_context(context);

}
END_TEST

START_TEST(test_pph_unlock_password_data_correct_thresholds){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned int i;
  unsigned int username_count=5;
  uint8 secret[DIGEST_LENGTH];

  const uint8 *usernames[] = {"username1",
                              "username12",
                              "username1231",
                              "username26",
                              "username5",
                            };
  const uint8 *passwords[] = {"password1",
                              "password12",
                              "password1231",
                              "password26",
                              "password5"
                              };

  
  const uint8 *usernames_subset[] = { "username12",
                                      "username26"};

  const uint8 *password_subset[] = {"password12",
                                    "password26"};

  // setup the context 
  context = pph_init_context(threshold,partial_bytes);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  //backup the secret
  memcpy(secret,context->secret,DIGEST_LENGTH);

  for(i=0;i<username_count;i++){
    pph_create_account(context,usernames[i], strlen(usernames[i]), passwords[i],
          strlen(passwords[i]),1);
  }

  // let's imagine it's all broken
  context->is_unlocked = 0;
  strcpy(context->secret,"thiswasnotthesecretstring");

  // now give a correct full account information, we expect to have our secret
  // back. 
  error = pph_unlock_password_data(context, username_count, usernames,
      passwords);
  for(i=0;i<DIGEST_LENGTH;i++){
    ck_assert(secret[i] ==  context->secret[i]);
  }

  // let's imagine it's all broken (Again)
  context->is_unlocked = 0;
  strcpy(context->secret,"thiswasnotthesecretstring");

  // now give a correct full account information, we expect to have our secret
  // back. 
  error = pph_unlock_password_data(context, 2, usernames_subset,
      password_subset);
  for(i=0;i<DIGEST_LENGTH;i++){
    ck_assert(secret[i] ==  context->secret[i]);
  }


  // and last but not least, create a superuser account and unlock it 
  // by himself
  pph_create_account(context,"ipicklocks", strlen("ipicklocks"),"ipickpockets",
      strlen("ipickpockets"), 3);
  error = pph_unlock_password_data(context, 1 ,strdup("ipicklocks"),
      strdup("ipickpockets"));
  
  for(i=0;i<DIGEST_LENGTH;i++){
    ck_assert(secret[i] ==  context->secret[i]);
  }


  // clean up our mess
  pph_destroy_context(context);
}
END_TEST

// test input sanity on the store function
START_TEST(test_pph_store_context_input_sanity){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned int i;

  error = pph_store_context(NULL,"pph.db");
  ck_assert_msg(error == PPH_BAD_PTR, " expected BAD_PTR");

  context = pph_init_context(threshold, partial_bytes);
  
  error = pph_store_context(context, NULL);
  ck_assert_msg(error == PPH_BAD_PTR, " expected BAD_PTR");

  error = pph_store_context(context, "pph.db");
  ck_assert_msg(error == PPH_ERROR_OK," expected ERROR_OK");

}END_TEST

// test input sanity on the store function
START_TEST(test_pph_reload_context_input_sanity){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned int i;

  context = pph_reload_context(NULL);
  
  ck_assert_msg(context == NULL, " expected to break with a null argument");

  context = pph_reload_context("nonexistent_file");
  
  ck_assert_msg(context == NULL, " expected to break with a nonexistent file");

  context = pph_reload_context("pph.db");
  ck_assert_msg(context != NULL, " this should've produced a valid pointer");
  ck_assert_msg(context->threshold == 2, " threshold didn't match the one set");
  ck_assert_msg(context->partial_bytes == 0, "partial bytes don't match");
  ck_assert_msg(context->secret == NULL, " didnt' store null for secret");
  ck_assert_msg(context->is_unlocked == 0, " loaded a seemingly valid context");
  
  pph_destroy_context(context);

}END_TEST

START_TEST(test_pph_store_and_reload_with_users){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
  uint8 secret[DIGEST_LENGTH]; 
  unsigned int i;
  unsigned int username_count=5;
  const uint8 *usernames[] = {"username1",
                              "username12",
                              "username1231",
                              "username26",
                              "username5",
                            };
  const uint8 *passwords[] = {"password1",
                              "password12",
                              "password1231",
                              "password26",
                              "password5"
                              };

  
  const uint8 *usernames_subset[] = { "username12",
                                      "username26"};

  const uint8 *password_subset[] = {"password12",
                                    "password26"};

  // setup the context 
  context = pph_init_context(threshold, partial_bytes);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  for(i=0;i<username_count;i++){
    pph_create_account(context,usernames[i], strlen(usernames[i]),passwords[i],
          strlen(passwords[i]),1);
  }
  
  // backup our secret
  memcpy(secret,context->secret,DIGEST_LENGTH);

  // let's store our data!
  error = pph_store_context(context,"pph.db");
  ck_assert_msg(error == PPH_ERROR_OK, " couldn't store a ctx with users");
  

  pph_destroy_context(context); // we will reload it now...


  context = pph_reload_context("pph.db");
  ck_assert_msg(context != NULL, " all is fine, so far...");
  // now give a correct full account information, we expect to have our secret
  // back. 
  pph_account_node *user_nodes;
  user_nodes = context->account_data;
  error = pph_unlock_password_data(context, username_count, usernames,
      passwords);
  for(i=0;i<DIGEST_LENGTH;i++){
    ck_assert(secret[i]==context->secret[i]);
  }

  // clean up our mess
  pph_destroy_context(context);

  context = pph_reload_context("pph.db");
  // if i ever get the gnome help from pressing f1 by mistake again i'm going
  // to kill someone. 
  ck_assert_msg(context != NULL, " loading broke");
  // now give a correct full account information, we expect to have our secret
  // back. 
  error = pph_unlock_password_data(context, 2, usernames_subset,
        password_subset);
  for(i=0;i<DIGEST_LENGTH;i++){
    ck_assert(secret[i]==context->secret[i]);
  }

  pph_destroy_context(context);
}
END_TEST




Suite * polypasshash_suite(void)
{
  Suite *s = suite_create ("buildup");

  /* no partial bytes case */
  TCase *tc_non_partial = tcase_create ("non-partial");
  tcase_add_test (tc_non_partial,test_pph_init_context_wrong_threshold);
  tcase_add_test (tc_non_partial,test_pph_init_context_no_partial_bytes);
  
  // creating an account 
  tcase_add_test (tc_non_partial,test_create_account_context);
  tcase_add_test (tc_non_partial,test_create_account_usernames);
  tcase_add_test (tc_non_partial,test_create_account_passwords);
  tcase_add_test (tc_non_partial,test_create_account_sharenumbers);
  tcase_add_test (tc_non_partial,test_create_account_entry_consistency);
  tcase_add_test (tc_non_partial,test_create_account_entry_list_consistency);

  // checking for an existing account
  tcase_add_test (tc_non_partial,test_check_login_input_sanity);
  tcase_add_test (tc_non_partial,test_check_login_wrong_username);
  tcase_add_test (tc_non_partial,test_check_login_wrong_password);
  tcase_add_test (tc_non_partial,test_check_login_proper_data);
  suite_add_tcase (s, tc_non_partial);

  /* vault unlocking (for both cases) */
  TCase *tc_unlock_shamir = tcase_create ("unlock_shamir");
  tcase_add_test (tc_unlock_shamir, test_pph_unlock_password_data_input_sanity);
  tcase_add_test (tc_unlock_shamir, 
      test_pph_unlock_password_data_correct_thresholds);
  suite_add_tcase (s, tc_unlock_shamir);

  /* pph context persistency tests */
  TCase *tc_store_context = tcase_create ("store_context");
  tcase_add_test( tc_store_context, test_pph_store_context_input_sanity);
  tcase_add_test( tc_store_context, test_pph_reload_context_input_sanity);
  tcase_add_test( tc_store_context, test_pph_store_and_reload_with_users);
  suite_add_tcase (s, tc_store_context);

  return s;
}

int main (void)
{
  int number_failed;
  Suite *s =  polypasshash_suite();
  SRunner *sr = srunner_create (s);
  srunner_run_all (sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


