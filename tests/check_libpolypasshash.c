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

START_TEST(test_pph_init_context_wrong_threshold)
{
}
END_TEST


START_TEST(test_pph_init_context_wrong_secret_length)
{
}
END_TEST


START_TEST(test_pph_init_context_wrong_secret_pointer)
{
}
END_TEST


START_TEST(test_pph_init_context_no_partial_bytes)
{
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


