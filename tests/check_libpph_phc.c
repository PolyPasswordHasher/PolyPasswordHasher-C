/* Check the PHS function for the password hashing competition.
 *
 * @author  Santiago Torres
 * @date    03/27/2014 
 * @license MIT
 */
#include<check.h>
#include"libgfshare.h"
#include"libpolypasshash.h"
#include<stdlib.h>
#include<strings.h>


// we will test for extraneous input on the PHS function first
START_TEST(test_PHS_extraneous_input)
{ 
  int returnval;
  uint8 output[DIGEST_LENGTH];
  uint8 salt[SALT_LENGTH];
  uint8 password[] = {"testpassword"};
  // test for null pointers
  returnval = PHS(output, DIGEST_LENGTH, password, strlen(password), NULL,
      SALT_LENGTH, 0, 0);
  ck_assert(returnval == -1);

  returnval = PHS(NULL, DIGEST_LENGTH, password, strlen(password), salt, 
      SALT_LENGTH, 0,0);
  ck_assert(returnval == -1);

  returnval = PHS(output, DIGEST_LENGTH, NULL, strlen(password), salt,
     SALT_LENGTH, 0, 0);
  ck_assert(returnval == -1);
  
  // now let's test for wrong values in the length parameters
  returnval = PHS(output, DIGEST_LENGTH + 1, password, strlen(password), salt,
     SALT_LENGTH, 0, 0);
  ck_assert(returnval == -1);

  returnval = PHS(output, 0, password, strlen(password), salt, SALT_LENGTH, 0,
     0);
  ck_assert(returnval == -1);

  returnval = PHS(output, DIGEST_LENGTH, password, 0, salt, SALT_LENGTH, 0, 0);
  ck_assert(returnval == -1);

  returnval = PHS(output, DIGEST_LENGTH, password, PASSWORD_LENGTH +1, salt,
     SALT_LENGTH, 0, 0);
  ck_assert(returnval == -1);

  returnval = PHS(output, DIGEST_LENGTH, password, strlen(password), salt,
    0, 0, 0);
  ck_assert(returnval == -1);

  returnval = PHS(output, DIGEST_LENGTH, password, strlen(password), salt,
     SALT_LENGTH + 1, 0, 0);
  ck_assert(returnval == -1);

  // lets do a valid generation, we should get a 0 error
  returnval = PHS(output, DIGEST_LENGTH, password, strlen(password), salt,
     SALT_LENGTH, 0, 0);
  ck_assert(returnval == 0); 
  
}
END_TEST





// We will now test the generated input with non-ascii ranges.
START_TEST(test_PHS_input_ranges)
{

}
END_TEST






// We will try to see if there are information leakages depending on the
// input.
START_TEST(test_PHS_timing)
{

}
END_TEST





// suite declaration
Suite * polypasshash_PHS_suite(void)
{
  Suite *s = suite_create ("PHS");

  // Input consistency, ranges and speed
  TCase *tc_phs = tcase_create ("phs_inputs");
  tcase_add_test(tc_phs, test_PHS_extraneous_input);
  tcase_add_test(tc_phs, test_PHS_input_ranges);
  tcase_add_test(tc_phs, test_PHS_timing);
  suite_add_tcase (s, tc_phs);

  return s;
}

int main (void)
{
  int number_failed;
  Suite *s =  polypasshash_PHS_suite();
  SRunner *sr = srunner_create (s);
  srunner_run_all (sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


