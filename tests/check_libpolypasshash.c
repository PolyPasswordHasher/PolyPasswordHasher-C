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
#include<stdlib.h>
#include<strings.h>

START_TEST(test_buildup)
{
}
END_TEST




Suite * polypasshash_suite(void)
{
  Suite *s = suite_create ("buildup");

  /* Core test case */
  TCase *tc_core = tcase_create ("core");
  tcase_add_test (tc_core,test_buildup);
  suite_add_tcase (s, tc_core);

  return s;
}

int main (void)
{
  int number_failed;
  Suite *s = shamir_suite();
  SRunner *sr = srunner_create (s);
  srunner_run_all (sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


