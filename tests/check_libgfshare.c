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

START_TEST(generate_secrets)
{
  int ok = 1, i;
  unsigned char* secret = (unsigned char*)strdup("hello");
  unsigned char* share1 = malloc(512);
  unsigned char* share2 = malloc(512);
  unsigned char* share3 = malloc(512);
  unsigned char* recomb = malloc(512);
  unsigned char* sharenrs = (unsigned char*)strdup("0123");
  gfshare_ctx *G; 
  
  G = gfshare_ctx_init_enc( sharenrs, 4, 2, 512);

  gfshare_ctx_enc_setsecret(G, secret);
  gfshare_ctx_enc_getshare( G, 0, share1);
  gfshare_ctx_enc_getshare( G, 1, share2);
  gfshare_ctx_enc_getshare( G, 2, share3);

  gfshare_ctx_free(G);

  G = gfshare_ctx_init_dec( sharenrs, 2, 512);
  gfshare_ctx_dec_giveshare( G, 0, share1);
  gfshare_ctx_dec_giveshare( G, 1, share2);

  sharenrs[2] = 0;
  gfshare_ctx_dec_newshares( G, sharenrs );
  gfshare_ctx_dec_extract( G, recomb);
  
  ck_assert_str_eq(secret,recomb);
}
END_TEST


START_TEST(generate_secrets_256_shares)
{
  int ok = 1, i;
  unsigned char* secret = (unsigned char*)strdup("hello");
  unsigned char* share1 = malloc(512);
  unsigned char* share2 = malloc(512);
  unsigned char* share3 = malloc(512);
  unsigned char* recomb = malloc(512);
  unsigned char* sharenrs = malloc(256);
  unsigned char random_shares[3];
  gfshare_ctx *G;

  for(i=0;i<256;i++){
    sharenrs[i] = (i+1)%255;
  }

  
  G = gfshare_ctx_init_enc( sharenrs, 254, 2, 512);

  gfshare_ctx_enc_setsecret(G, secret);
  gfshare_ctx_enc_getshare( G, 0, share1);
  gfshare_ctx_enc_getshare( G, 1, share2);
  gfshare_ctx_enc_getshare( G, 2, share3);

  gfshare_ctx_free(G);

  G = gfshare_ctx_init_dec( sharenrs, 2, 512);
  gfshare_ctx_dec_giveshare( G, 0, share1);
  gfshare_ctx_dec_giveshare( G, 1, share2);
  gfshare_ctx_dec_giveshare( G, 2, share3);

  random_shares[0]=1;
  random_shares[1]=2;
  random_shares[2]=3;
    
  gfshare_ctx_dec_newshares( G, random_shares );
  gfshare_ctx_dec_extract( G, recomb);

  ck_assert_str_eq(recomb,secret);
 
}
END_TEST




Suite * shamir_suite (void)
{
  Suite *s = suite_create ("split");

  /* Core test case */
  TCase *tc_core = tcase_create ("core");
  tcase_add_test (tc_core,generate_secrets);
  tcase_add_test (tc_core,generate_secrets_256_shares);
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


