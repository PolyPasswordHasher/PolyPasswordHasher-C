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
#include<stdio.h>

START_TEST(generate_secrets)
{
  int ok = 1, i;
  unsigned char* secret = (unsigned char*)strdup("hello");
  unsigned char* share1 = malloc(512);
  unsigned char* share2 = malloc(512);
  unsigned char* share3 = malloc(512);
  unsigned char* recomb = malloc(512);
  unsigned char* sharenrs = (unsigned char*)strdup("012");
  gfshare_ctx *G;



  
  G = gfshare_ctx_init_enc( sharenrs, 3, 2, 512);

  gfshare_ctx_enc_setsecret(G, secret);
  gfshare_ctx_enc_getshare( G, 0, share1);
  gfshare_ctx_enc_getshare( G, 1, share2);
  gfshare_ctx_enc_getshare( G, 2, share3);

  
  for(i=0; i<512; i++){
    printf("%hhu", share1[i]);
  }

  printf("\n");
  gfshare_ctx_free(G);

  G = gfshare_ctx_init_dec( sharenrs, 3, 512);
  gfshare_ctx_dec_giveshare( G, 0, share1);
  gfshare_ctx_dec_giveshare( G, 1, share2);
  gfshare_ctx_dec_giveshare( G, 2, share3);

  sharenrs[2] = 0;
  gfshare_ctx_dec_newshares( G, sharenrs );
  gfshare_ctx_dec_extract( G, recomb);
  for( i=0; i<strlen(secret); i++){
    printf(" (%hhu,%hhu) ",secret[i],recomb[i]);
  }
}
END_TEST

Suite * shamir_suite (void)
{
  Suite *s = suite_create ("split");

  /* Core test case */
  TCase *tc_core = tcase_create ("core");
  //tcase_add_checked_fixture (tc_core, setup, teardown);
  tcase_add_test (tc_core,generate_secrets);
  suite_add_tcase (s, tc_core);

  /* Limits test case */
  //TCase *tc_limits = tcase_create ("limits");
  //tcase_add_test (tc_limits, test_money_create_neg);
  //tcase_add_test (tc_limits, test_money_create_zero);
  //suite_add_tcase (s, tc_limits);

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


