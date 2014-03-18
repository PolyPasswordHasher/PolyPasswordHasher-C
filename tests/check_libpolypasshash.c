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
  uint8 *secret = "secretstring";// this is not necesarilly a string, but will
                                 // work for demonstration purposes
  unsigned int length = strlen(secret);
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  context = pph_init_context(threshold, secret, length, partial_bytes);

  ck_assert_msg(context == NULL,
      "the context returned upon a wrong threshold value should be NULL");
  
}
END_TEST

// the only possble method we have to discern whether the lentgth for the pass-
// word is wrong, is through the defined constant PASSWORD-LENGTH and 0, we 
// will expect to get a NULL with both checks (if bigger than or shorter than)
START_TEST(test_pph_init_context_wrong_secret_length)
{
  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 *secret = "secretstring";// this is not necesarilly a string, but will
                                 // work for demonstration purposes
  unsigned int length = PASSWORD_LENGTH+1; //wooops
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  context = pph_init_context(threshold, secret, length, partial_bytes);

  ck_assert_msg(context == NULL,
      "the context returned upon a wrong length value should be NULL");
  
  
  length = 0;
    
  context = pph_init_context(threshold, secret, length, partial_bytes);
  
  ck_assert_msg(context == NULL,
      "the context returned upon a 0 length value should be NULL");
  
}
END_TEST

// in this case, we mistakenly give a wrong pointer for the secret message
// we should get an unitialized context.
START_TEST(test_pph_init_context_wrong_secret_pointer)
{
  // a placeholder for the result.
  pph_context *context;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 *secret = "secretstring";// this is not necesarilly a string, but will
                                 // work for demonstration purposes
  unsigned int length = strlen(secret); // this is good and valid
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          

  context = pph_init_context(threshold, NULL /*woops*/, length, partial_bytes);

  ck_assert_msg(context == NULL,
      "the context returned upon a wrong length value should be NULL");
 
}
END_TEST


START_TEST(test_pph_init_context_no_partial_bytes)
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
                          

  context = pph_init_context(threshold, secret, length, partial_bytes);

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
  error = pph_create_account(NULL, "mr.user", "yessir,verysecure", 1);
  
  ck_assert_msg(error == PPH_BAD_PTR, 
      "We should've gotten BAD_PTR in the return value");
  
}
END_TEST

// this test is intended to check correct sanity check on the username field
START_TEST(test_create_account_usernames){
  pph_context *context;
  PPH_ERROR error;
  uint8 threshold = 2; // we have a correct threshold value for this testcase 
  uint8 *secret = "secretstring";// this is not necesarilly a string, but will
                                 // work for demonstration purposes
  unsigned int length = strlen(secret); // this is good and valid
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
  

  unsigned char username[USERNAME_LENGTH+1];
  unsigned int i;
  for(i=0;i<USERNAME_LENGTH;i++){
    username[i] = 'k'; // endless string
  }
  username[USERNAME_LENGTH] = '\0';

  // initialize a correct context from scratch
  context = pph_init_context(threshold, secret, length, partial_bytes);
  
  // sending bogus information to the create user function.
  error = pph_create_account(context, username, "yessir,verysecure", 1);
  
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
  uint8 *secret = "secretstring";// this is not necesarilly a string, but will
                                 // work for demonstration purposes
  unsigned int length = strlen(secret); // this is good and valid
  uint8 partial_bytes = 0;// this function is part of the non-partial bytes
                          // suite
                          
  unsigned char password[PASSWORD_LENGTH+1];
  unsigned int i;
 
  context = pph_init_context(threshold, secret, length, partial_bytes);

  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  
 for(i=0;i<PASSWORD_LENGTH;i++){
    password[i] = 'k'; // endless string of k's
  }
  password[PASSWORD_LENGTH] = '\0';
  // sending bogus information to the create user function.
  error = pph_create_account(context, "ichooseverylongpasswords",
       password,1);
  
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
  error = pph_create_account(context, username, password,1);
  
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should've gotten PPH_ERROR_OK in the return value");
  

  ck_assert_str_eq(username,context->account_data->account.username);

  // now lets check we can take the digest back from the death... I mean
  // share
  memcpy(salted_password,context->account_data->account.entries->salt,
      SALT_LENGTH);
  _calculate_digest(password_digest, salted_password);
  digest_result=context->account_data->account.entries->hashed_value;

  gfshare_ctx_enc_getshare(context->share_context, 1, share_result);
  _xor_share_with_digest(digest_result, share_result, digest_result, 
      DIGEST_LENGTH);

  for(i=0;i<DIGEST_LENGTH;i++){
    ck_assert(password_digest[i]==digest_result[i]);
  }

  // we will check for the existing account error handler now...
  error = pph_create_account(context, username, password,1);

  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      "We should've gotten an error since this account repeats");
  
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
}
END_TEST

// This checks for a proper return code when asking for the wrong username
START_TEST(test_check_login_wrong_username){
}
END_TEST


// This checks for a proper return code when providing a wrong password 
START_TEST(test_check_login_wrong_password){
}
END_TEST

// This checks for a proper behavior when providing an existing username, 
// first, as the first and only username, then after having many on the list
START_TEST(test_check_login_proper_data){
}
END_TEST


Suite * polypasshash_suite(void)
{
  Suite *s = suite_create ("buildup");

  /* no partial bytes case */
  TCase *tc_non_partial = tcase_create ("non-partial");
  tcase_add_test (tc_non_partial,test_pph_init_context_wrong_threshold);
  tcase_add_test (tc_non_partial,test_pph_init_context_wrong_secret_length);
  tcase_add_test (tc_non_partial,test_pph_init_context_wrong_secret_pointer);
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


