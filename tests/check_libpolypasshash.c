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
  
}
END_TEST

// this test is intended to check correct sanity check on the username field
START_TEST(test_create_account_usernames){
}
END_TEST

// this test is intended to check correct sanity checks on the password fields
START_TEST(test_create_account_passwords){
}
END_TEST
// this test is intended to check the correct sanity check on the sharenumber
// field
START_TEST(test_create_account_sharenumbers){
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


