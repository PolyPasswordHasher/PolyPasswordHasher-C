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
  
  printf("\n%d\n",error);
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
  unsigned int i;
 
  context = pph_init_context(threshold, secret, length, partial_bytes);

  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // sending bogus information to the create user function.
  error = pph_create_account(context, username, password,1);
  
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should've gotten PPH_ERROR_OK in the return value");
  
//  printf("------->%p",context->account_data);

  ck_assert_str_eq(username,context->account_data->account.username);
  puts("6ddbb91a63b88bad59b108fa7a4b236155f5b1b1dd2dc9580798624dcbc2dcee");
  for(i=0;i<DIGEST_LENGTH;i++){
    printf("%02x",context->account_data->account.entries->hashed_value[i]);
  }

  error = pph_destroy_context(context);

  ck_assert_msg(error == PPH_ERROR_OK, 
      "the free function didn't work properly");


}
END_TEST
// this test is intended to check that a correct account structure is 
// producted (i.e. hash, etc.)
START_TEST(test_create_account_entry_consistency){
}
END_TEST

// this test is intended to check that the linked list is correctly created,
// checks for correct number of entries and username collisions
START_TEST(test_create_account_entry_list_consistency){
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
  
  tcase_add_test (tc_non_partial,test_create_account_context);
  tcase_add_test (tc_non_partial,test_create_account_usernames);
  tcase_add_test (tc_non_partial,test_create_account_passwords);
  tcase_add_test (tc_non_partial,test_create_account_sharenumbers);
  tcase_add_test (tc_non_partial,test_create_account_entry_consistency);
  tcase_add_test (tc_non_partial,test_create_account_entry_list_consistency);
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


