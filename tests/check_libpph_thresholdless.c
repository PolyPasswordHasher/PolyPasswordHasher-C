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

// We tests that a correst AES key is generated during the init_context 
// function
START_TEST(test_pph_init_context_AES_key)
{ 
  pph_context *context; // the context to instantiate
  uint8 threshold;      // the threshold of our data store
  unsigned char *secret = "secretstring";

  unsigned int length = strlen(secret);;
  uint8 partial_bytes = 0;

  context = pph_init_context(threshold, secret, length, partial_bytes);

  ck_assert_msg( context != NULL, " couldn't initialize the pph context" );
  ck_assert_msg( context->AES_key != NULL, "the key wansn't generated properly");

}
END_TEST

// this might be overchecking, but we want to make sure it destroy the AES key
// properly. TODO: consider if the key should be zeroed out before releasing
START_TEST(test_pph_destroy_context_AES_key)
{
  // a placeholder for the result.
  pph_context *context;
  PPH_ERROR error;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 *secret = "secretstring";// this is not necesarilly a string, but will
                                 // work for demonstration purposes
  unsigned int length = strlen(secret); // this is good and valid
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          

  context = pph_init_context(threshold, NULL /*woops*/, length, partial_bytes);

  ck_assert_msg(context == NULL,
      "the context returned upon a wrong length value should be NULL");
  ck_assert_msg(context->AES_key != NULL, " the key wasn't generated properly");

  error = pph_destroy_context(context);
  ck_assert(error == PPH_ERROR_OK); 

}
END_TEST

// We will test some account creation now...
START_TEST(test_pph_create_accounts)
{
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 *secret = "secretstring";// this is not necesarilly a string, but will
                                 // work for demonstration purposes
  unsigned int length = strlen(secret); // this is good and valid
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned char password[] = "verysecure";
  unsigned char username[] = "atleastitry";
  unsigned char salted_password[] = {'x','x','x','x','x','x','x','x','x','x',
                                     'x','x','x','x','x','x','v','e','r','y',
                                     's','e','c','u','r','e','\0'};
  // this is the calculated hash for the password without salt using 
  // an external tool
  uint8 password_digest[DIGEST_LENGTH]; 
  unsigned int i;
  uint8 *digest_result;
  uint8 share_result[SHARE_LENGTH];

  context = pph_init_context(threshold, secret, length, partial_bytes);

  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // sending bogus information to the create user function.
  error = pph_create_account(context, username, password,0); // THL account. 
  
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should've gotten PPH_ERROR_OK in the return value");
  

  ck_assert_str_eq(username,context->account_data->account.username);

  // now lets check there are colissions between thl and non thl accounts
  error = pph_create_account(context, username, password,1);

  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      "We should've gotten an error since this account repeats");
  
  // finally, check it returns the proper error code if the vault is locked
  // still
  context->is_unlocked = 0; // we simulate locking by setting the flag
                            // manually,
  context->AES_key = NULL;
  // we will check for the existing account error handler now...
  error = pph_create_account(context, "someotherguy",
      "came-here-asking-the-same-thing",0);

  ck_assert_msg(error == PPH_CONTEXT_IS_LOCKED, 
      "We should've gotten an error now that the vault is locked");
 
  error = pph_destroy_context(context);
  
  ck_assert_msg(error == PPH_ERROR_OK, 
      "the free function didn't work properly");
}
END_TEST

// this test is intended to check that the linked list is correctly created,
// checks for correct number of entries and username collisions
START_TEST(test_create_account_mixed_accounts){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 *secret = "secretstring";// this is not necesarilly a string, but will
                                 // work for demonstration purposes
  unsigned int length = strlen(secret); // this is good and valid
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned char password[] = "verysecure";
  unsigned char username[] = "atleastitry";
  unsigned char salted_password[] = {'x','x','x','x','x','x','x','x','x','x',
                                     'x','x','x','x','x','x','v','e','r','y',
                                     's','e','c','u','r','e','\0'};
  // this is the calculated hash for the password without salt using 
  // an external tool
  uint8 password_digest[DIGEST_LENGTH]; 
  unsigned int i;
  uint8 *digest_result;
  uint8 share_result[SHARE_LENGTH];

  context = pph_init_context(threshold, secret, length, partial_bytes);

  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // sending bogus information to the create user function.
  error = pph_create_account(context, username, password,0); // THL account. 
  
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should've gotten PPH_ERROR_OK in the return value");
  
  ck_assert_str_eq(username,context->account_data->account.username);
  
  // now let's create a bunch of accounts with thresholds this time

  error = pph_create_account(context, "johhnyjoe", "passwording",1);
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should've gotten PPH_ERROR_OK in the return value");
   error = pph_create_account(context, "richardWalkins", "i'm-unreliable",5);
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should've gotten PPH_ERROR_OK in the return value");
  
}
END_TEST


// This checks for a proper behavior when providing an existing username, 
// first, as the first and only username, then after having many on the list
START_TEST(test_check_login_thresholdless){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 *secret = "secretstring";// this is not necesarilly a string, but will
                                 // work for demonstration purposes
  unsigned int length = strlen(secret); // this is good and valid
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned char password[] = "i'mnothere";
  unsigned char username[] = "nonexistentpassword";
  unsigned char anotheruser[] = "0anotheruser";
  unsigned int i;

  // setup the context 
  context = pph_init_context(threshold, secret, length, partial_bytes);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  

  // add a single user and see how it behaves:
  // 1) add a user
  error = pph_create_account(context, username, password, 0);
  ck_assert_msg(error == PPH_ERROR_OK, " this shouldn't have broken the test");

  // 2) ask for it, providing correct credentials
  error = pph_check_login(context, username, password);
  ck_assert_msg(error == PPH_ERROR_OK, 
      "expected OK");
  
  
  // lets add a whole bunch of users and check for an existing one again
  // 1) add a whole new bunch of users:
  for(i=1;i<9;i++){
    anotheruser[0] = i+48;
    error = pph_create_account(context, anotheruser, "anotherpassword", 1);
    ck_assert_msg(error == PPH_ERROR_OK,
        " this shouldn't have broken the test");
  }


  // 2) ask again, in a sea of admins :(
  error = pph_check_login(context, username, password);
  ck_assert_msg(error == PPH_ERROR_OK, 
      "expected ERROR_OK");
  
  // 3) ask one more time, mistyping our passwords
  error = pph_check_login(context, username, "i'mnotthere");
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, " how did we get in!?");

  // 4) check if thresholdfull accounts can login (they should)
  error = pph_check_login(context, "0anotheruser", "anotherpassword");
  ck_assert_msg(error == PPH_ERROR_OK,
      " we should've been able to login as admin");

  // clean up our mess.
  pph_destroy_context(context);
}
END_TEST

// shamir recombination procedure test cases, we should get out key back!
START_TEST(test_pph_unlock_password_data){
  PPH_ERROR error;

  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 *secret = "secretstring";// this is not necesarilly a string, but will
                                 // work for demonstration purposes
  unsigned int length = strlen(secret); // this is good and valid
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
  const uint8 *usernames_subset[] = { "username12",
                                      "username26"};

  const uint8 *password_subset[] = { "password12",
                                     "password26"};

  uint8 key_backup[DIGEST_LENGTH];

  // check for bad pointers at first
  error = pph_unlock_password_data(NULL, username_count, usernames, passwords);
  ck_assert_msg(error == PPH_BAD_PTR," EXPECTED BAD_PTR");

  // setup the context 
  context = pph_init_context(threshold, secret, length, partial_bytes);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // backup the key...
  memcpy(key_backup,context->AES_key,DIGEST_LENGTH);
  
  // let's pretend all is broken
  context->is_unlocked =0;
  context->AES_key = NULL;
  context->secret = NULL;

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


  // now give a correct full account information, we expect to have our secret
  // back. 
  error = pph_unlock_password_data(context, username_count, usernames,
      passwords);
  ck_assert(error = PPH_ERROR_OK);
  ck_assert_msg(context->secret !=NULL, " didnt allocate the secret!");
  ck_assert_str_eq(secret, context->secret);
  ck_assert(context->AES_key != NULL);
  for(i=0;i<DIGEST_LENGTH;i++){
    ck_assert(key_backup[i] == context->AES_key[i]);
  }


  // let's imagine it's all broken (Again)
  context->is_unlocked = 0;
  context->AES_key = NULL;
  context->secret = NULL;

  // now give a correct full account information, we expect to have our secret
  // back. 
  error = pph_unlock_password_data(context, 2, usernames_subset,
      password_subset);
  ck_assert(error = PPH_ERROR_OK);
  ck_assert_msg(context->secret !=NULL, " didnt allocate the secret!");
  ck_assert_str_eq(secret, context->secret);
  ck_assert(context->AES_key != NULL);
  for(i=0;i<DIGEST_LENGTH;i++){
    ck_assert(key_backup[i] == context->AES_key[i]);
  } 

  pph_destroy_context(context);
}
END_TEST


Suite * polypasshash_thl_suite(void)
{
  Suite *s = suite_create ("thresholdless");

  /* no partial bytes case */
  TCase *tc_non_partial = tcase_create ("non-partial");
  tcase_add_test (tc_non_partial,test_pph_init_context_AES_key);
  tcase_add_test (tc_non_partial,test_pph_destroy_context_AES_key);
  tcase_add_test (tc_non_partial,test_pph_create_accounts);
  tcase_add_test (tc_non_partial,test_create_account_mixed_accounts);
  tcase_add_test (tc_non_partial,test_check_login_thresholdless);
  tcase_add_test (tc_non_partial,test_pph_unlock_password_data);
  suite_add_tcase (s, tc_non_partial);

  return s;
}

int main (void)
{
  int number_failed;
  Suite *s =  polypasshash_thl_suite();
  SRunner *sr = srunner_create (s);
  srunner_run_all (sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


