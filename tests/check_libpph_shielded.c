/* Check libpolypasswordhasher with the shielded extension
 *
 * The shielded extension is tested in this suite
 *
 * @author  Santiago Torres
 * @date    10/03/2014
 * @license MIT
 */


#include<check.h>
#include"libgfshare.h"
#include"libpolypasswordhasher.h"
#include<stdlib.h>
#include<strings.h>






// We test that a correct AES key is generated during the pph_init_context 
// function
START_TEST(test_pph_init_context_AES_key)
{


  pph_context *context; 
  uint8 threshold = 2; 
  uint8 isolated_check_bits = 0;


  context = pph_init_context(threshold, isolated_check_bits);

  ck_assert_msg( context != NULL, " couldn't initialize the pph context" );
  ck_assert_msg( context->AES_key != NULL, "the key wansn't generated properly");

}
END_TEST





// this might be overchecking, but we want to make sure it destroys the AES key
// properly. 
START_TEST(test_pph_destroy_context_AES_key)
{


  pph_context *context;
  PPH_ERROR error;
  uint8 threshold = 2; 
  uint8 isolated_check_bits = 0;
                          

  context = pph_init_context(threshold, isolated_check_bits);

  ck_assert_msg(context != NULL, " shouldn't break here");
  ck_assert_msg(context->AES_key != NULL, " the key wasn't generated properly");

  error = pph_destroy_context(context);
  ck_assert(error == PPH_ERROR_OK); 

}
END_TEST





// We will test some account creation, with only shielded accounts. 
START_TEST(test_pph_create_accounts)
{


  PPH_ERROR error;
  pph_context *context;
  uint8 threshold = 2; 
  uint8 isolated_check_bits = 0;
  unsigned char password[] = "verysecure";
  unsigned char username[] = "atleastitry";
  
  
  context = pph_init_context(threshold, isolated_check_bits);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
 
  // attempt to create a shielded account now. 
  error = pph_create_account(context, username, strlen(username),
      password, strlen(password), 0);  
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should've gotten PPH_ERROR_OK in the return value");
  context->account_data->account.username[strlen(username)]='\0';
  ck_assert_str_eq(username,context->account_data->account.username);

  // now lets check there are collisions between threshold and shielded
  // accounts
  error = pph_create_account(context, username, strlen(username), password,
      strlen(password), 1);
  ck_assert_msg(error == PPH_ACCOUNT_EXISTS, 
      "We should have gotten an error since this account repeats");
  
  // finally, check it returns the proper error code if the vault is locked
  // still
  context->is_normal_operation = false; 
  context->AES_key = NULL;
  
  // This will create a bootstrap account...
  error = pph_create_account(context, "someotherguy", strlen("someotherguy"),
    "came-here-asking-the-same-thing",strlen("came-here-asking-the-same-thing"),
    0);
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should have gotten an error ok, since we created a bootstrap account");
 
  error = pph_destroy_context(context);
  ck_assert_msg(error == PPH_ERROR_OK, 
      "the free function didn't work properly");
}
END_TEST





// this test is intended to check that we can have both, shielded accounts
// and threshold accounts in a same context and working properly.
START_TEST(test_create_account_mixed_accounts) {


  PPH_ERROR error;
  pph_context *context;
  uint8 threshold = 2; 
  uint8 isolated_check_bits = 0;
                          
  unsigned char password[] = "verysecure";
  unsigned char username[] = "atleastitry";
  uint8 password_digest[DIGEST_LENGTH]; 
  unsigned int i;
  uint8 *digest_result;
  uint8 share_result[SHARE_LENGTH];


  context = pph_init_context(threshold, isolated_check_bits);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // Create a shielded account
  error = pph_create_account(context, username, strlen(username), password,
      strlen(password), 0); 
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should've gotten PPH_ERROR_OK in the return value");
  context->account_data->account.username[strlen(username)]='\0';
  ck_assert_str_eq(username,context->account_data->account.username);
  
  // now let's create a bunch of accounts with thresholds this time
  error = pph_create_account(context, "johhnyjoe", strlen("johhnyjoe"),
      "passwording", strlen("passwording"),1);
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should've gotten PPH_ERROR_OK in the return value");
   error = pph_create_account(context, "richardWalkins", 
       strlen("richardWalkins"),"i'm-unreliable", strlen("i'm-unreliable"),5);
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should've gotten PPH_ERROR_OK in the return value");
  
  pph_destroy_context(context);
}
END_TEST






// This checks for a proper behavior when providing an existing username, 
// first, as the first and only username, then after having many on the list
START_TEST(test_check_login_shielded) {


  PPH_ERROR error;
  pph_context *context;
  uint8 threshold = 2; 
  uint8 isolated_check_bits = 0;
  unsigned char password[] = "i'mnothere";
  unsigned char username[] = "nonexistentpassword";
  unsigned char anotheruser[] = "0anotheruser";
  unsigned int i;


  // setup the context 
  context = pph_init_context(threshold, isolated_check_bits);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // add a single user and see how it behaves:
  // 1) add a user
  error = pph_create_account(context, username, strlen(username), password,
     strlen(password), 0);
  ck_assert_msg(error == PPH_ERROR_OK, " this shouldn't have broken the test");

  // 2) ask for it, providing correct credentials
  error = pph_check_login(context, username, strlen(username), password,
      strlen(password));
  ck_assert_msg(error == PPH_ERROR_OK, 
      "expected OK");
  
  
  // lets add a whole bunch of users and check for an existing one again
  // 1) add a whole new bunch of users:
  for(i=1;i<9;i++) {
    error = pph_create_account(context, anotheruser, strlen(anotheruser),
        "anotherpassword", strlen("anotherpassword"),1);
    ck_assert_msg(error == PPH_ERROR_OK,
        " this shouldn't have broken the test");
    anotheruser[0] = i+48;
  }


  // 2) ask again.
  error = pph_check_login(context, username, strlen(username), password,
      strlen(password));
  ck_assert_msg(error == PPH_ERROR_OK, 
      "expected ERROR_OK");
  
  // 3) ask one more time, mistyping our passwords
  error = pph_check_login(context, username, strlen(username), "i'mnotthere",
      strlen("i'mnotthere"));
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, " how did we get in!?");

  // 4) check if protector accounts can login (they should)
  error = pph_check_login(context, "0anotheruser", strlen("0anotheruser"), 
    "anotherpassword", strlen("anotherpassword"));
  ck_assert_msg(error == PPH_ERROR_OK,
      " we should have been able to login as a threshold account");

  // 5) create a bootstrap account and log in.
  free(context->secret);
  context->secret = NULL;
  context->is_normal_operation = false;
  error = pph_create_account(context, "specialusername", strlen("specialusername"),
          "specialpassword", strlen("specialpassword"), 0);
  ck_assert(error == PPH_ERROR_OK);
  error = pph_check_login(context, "specialusername", strlen("specialusername"),
          "specialpassword", strlen("specialpassword"));
  ck_assert(error == PPH_ERROR_OK);


  // clean up our mess.
  pph_destroy_context(context);
}
END_TEST





// shamir recombination procedure test cases, we should get out key back!
START_TEST(test_pph_unlock_password_data) {


  PPH_ERROR error;
  pph_context *context;
  uint8 threshold = 2; 
  uint8 isolated_check_bits = 0;
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
  
  unsigned int username_lengths[] = { strlen("username1"),
                                      strlen("username12"),
                                      strlen("username1231"),
                                      strlen("username26"),
                                      strlen("username5"),
                                  };
  
  unsigned int password_lengths[] = { strlen("password1"),
                              strlen("password12"),
                              strlen("password1231"),
                              strlen("password26"),
                              strlen("password5")
                              };
  
  const uint8 *usernames_subset[] = { "username12",
                                      "username26"};
  
  unsigned int username_lengths_subset[] = { strlen("username12"),
                                            strlen("username26"),
                                            };
  const uint8 *password_subset[] = { "password12",
                                     "password26"};
  
  unsigned int password_subset_lengths[] = {strlen("password12"),
                                            strlen("password26")};
  
  
  uint8 key_backup[DIGEST_LENGTH];


  // check for bad pointers at first
  error = pph_unlock_password_data(NULL, username_count, usernames,
      username_lengths, passwords, password_lengths);
  ck_assert_msg(error == PPH_BAD_PTR," EXPECTED BAD_PTR");

  // setup the context 
  context = pph_init_context(threshold, isolated_check_bits);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // backup the key...
  memcpy(key_backup,context->AES_key,DIGEST_LENGTH);
   
  // store the accounts
  for(i=0;i<username_count;i++) {
    error = pph_create_account(context, usernames[i], strlen(usernames[i]),
        passwords[i], strlen(passwords[i]),1);
    ck_assert(error == PPH_ERROR_OK);
  }

  // let's pretend all is broken
  context->is_normal_operation = false;
  context->AES_key = NULL;
  context->secret = NULL;
  context->share_context= NULL;

  // now give a wrong username count, i.e. below the threshold.
  error = pph_unlock_password_data(context, 0, usernames, username_lengths,
      passwords, password_lengths);
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      " Expected ACCOUNT_IS_INVALID");

  // do it again, more graphical... 
  error = pph_unlock_password_data(context, threshold -1, usernames, 
      username_lengths, passwords, password_lengths);
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      " Expected ACCOUNT_IS_INVALID");

  // let's check for NULL pointers on the username and password fields
  error = pph_unlock_password_data(context, username_count, NULL,
     username_lengths, passwords, password_lengths);
  ck_assert_msg(error == PPH_BAD_PTR," EXPECTED BAD_PTR");

 
  // let's check for NULL pointers on the username and password fields
  error = pph_unlock_password_data(context, username_count, usernames, 
      username_lengths, NULL, password_lengths);
  ck_assert_msg(error == PPH_BAD_PTR," EXPECTED BAD_PTR");


  // now give correct account information, we expect to have our secret
  // back. 
  error = pph_unlock_password_data(context, username_count, usernames,
      username_lengths, passwords, password_lengths);
  ck_assert(error == PPH_ERROR_OK);
  ck_assert_msg(context->secret !=NULL, " didnt allocate the secret!");
  ck_assert(context->AES_key != NULL);


  // let's imagine it's all broken (Again)
  context->is_normal_operation = false;
  context->AES_key = NULL;
  context->secret = NULL;
  context->share_context = NULL;

  // now give correct account information, we expect to have our secret
  // back. 
  error = pph_unlock_password_data(context, 2, usernames_subset,
      username_lengths_subset, password_subset, password_subset_lengths);
  ck_assert(error == PPH_ERROR_OK);
  ck_assert_msg(context->secret !=NULL, " didnt allocate the secret!");
  ck_assert(context->AES_key != NULL);
  for(i=0;i<DIGEST_LENGTH;i++) {
    ck_assert(key_backup[i] == context->AES_key[i]);
  } 

  // check that we can login with a bootstrapped context.
  error = pph_check_login(context, usernames_subset[0], 
    strlen(usernames_subset[0]),password_subset[0], strlen(password_subset[0]));
  ck_assert(error == PPH_ERROR_OK);


  pph_destroy_context(context);
}
END_TEST




// We are going to test the full application lifecycle with a shielded
// account, by generating a new context, creating threshold accounts, creating
// a shielded account, saving the context, reloading the context, bootstrapping 
// the context and logging as a shielded account
START_TEST(test_pph_shielded_full_lifecycle){


  PPH_ERROR error;
  pph_context *context;
  uint8 threshold = 2; 
  uint8 isolated_check_bits = 0;
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
  
  unsigned int username_lengths[] = { strlen("username1"),
                                      strlen("username12"),
                                      strlen("username1231"),
                                      strlen("username26"),
                                      strlen("username5"),
                                  };
 
  unsigned int password_lengths[] = { strlen("password1"),
                              strlen("password12"),
                              strlen("password1231"),
                              strlen("password26"),
                              strlen("password5")
                              };
                              
  const uint8 *usernames_subset[] = { "username12",
                                      "username26"};
  
  unsigned int username_lengths_subset[] = { strlen("username12"),
                                            strlen("username26"),
                                            };
  
  const uint8 *password_subset[] = { "password12",
                                     "password26"};
  
   unsigned int password_subset_lengths[] = {strlen("password12"),
                                            strlen("password26")};
                                            
  uint8 key_backup[DIGEST_LENGTH];


  // check for bad pointers at first
  error = pph_unlock_password_data(NULL, username_count, usernames,
      username_lengths, passwords, password_lengths);
  ck_assert_msg(error == PPH_BAD_PTR," EXPECTED BAD_PTR");

  // setup the context 
  context = pph_init_context(threshold, isolated_check_bits);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // backup the key...
  memcpy(key_backup,context->AES_key,DIGEST_LENGTH);
   
  // store the accounts
  for(i=0;i<username_count;i++) {
    error = pph_create_account(context, usernames[i], strlen(usernames[i]),
        passwords[i], strlen(passwords[i]),1);
    ck_assert(error == PPH_ERROR_OK);
  }


  // create a shielded account
  error = pph_create_account( context, "shielded", strlen("shielded"),
      "shieldedpw", strlen("shieldedpw"), 0);
  ck_assert( error == PPH_ERROR_OK);

  // check that we can login with the shielded account
  error = pph_check_login(context, "shielded", strlen("shielded"),
      "shieldedpw", strlen("shieldedpw"));
  ck_assert( error == PPH_ERROR_OK);


  // store the context
  error = pph_store_context( context, "pph.db");
  ck_assert( error == PPH_ERROR_OK);
  pph_destroy_context(context);

  // reload the context
  context = pph_reload_context("pph.db");
  ck_assert( context != NULL);
 
  // let's check for NULL pointers on the username and password fields
  error = pph_unlock_password_data(context, username_count, usernames, 
      username_lengths, passwords, password_lengths);
  ck_assert_msg(error == PPH_ERROR_OK," EXPECTED PPH_ERROR_OK");


  // check that we can login with a bootstrapped context.
  error = pph_check_login(context, usernames_subset[0], 
    strlen(usernames_subset[0]),password_subset[0], strlen(password_subset[0]));
  ck_assert(error == PPH_ERROR_OK);

  // check that we can login with the shielded account
  error = pph_check_login(context, "shielded", strlen("shielded"),
      "shieldedpw", strlen("shieldedpw"));
  ck_assert( error == PPH_ERROR_OK);

  pph_destroy_context(context);


}END_TEST


// create a context and set it to bootstrapping. Create bootstrap accounts.
// transition to normal operation and verify that the accounts are updated.
START_TEST(test_pph_bootstrap_accounts)
{

  PPH_ERROR error;
  pph_context *context;
  uint8 threshold = 2; 
  uint8 isolated_check_bits = 0;
  pph_account_node *account_nodes;
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
  
  unsigned int username_lengths[] = { strlen("username1"),
                                      strlen("username12"),
                                      strlen("username1231"),
                                      strlen("username26"),
                                      strlen("username5"),
                                  };
  
  unsigned int password_lengths[] = { strlen("password1"),
                              strlen("password12"),
                              strlen("password1231"),
                              strlen("password26"),
                              strlen("password5")
                              };
                                                              
  const uint8 *usernames_subset[] = { "username12",
                                      "username26"};
                                      
  unsigned int username_lengths_subset[] = { strlen("username12"),
                                            strlen("username26"),
                                            };
                                            
  const uint8 *password_subset[] = { "password12",
                                     "password26"};
  
   unsigned int password_subset_lengths[] = {strlen("password12"),
                                            strlen("password26")};
                                            
  uint8 key_backup[DIGEST_LENGTH];

  // setup the context 
  context = pph_init_context(threshold, isolated_check_bits);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // backup the key...
  memcpy(key_backup,context->AES_key,DIGEST_LENGTH);
   
  // create some protector accounts...
  for(i=0;i<username_count;i++) {
    error = pph_create_account(context, usernames[i], strlen(usernames[i]),
        passwords[i], strlen(passwords[i]),1);
    ck_assert(error == PPH_ERROR_OK);
  }

  // store the context
  error = pph_store_context( context, "pph.db");
  ck_assert( error == PPH_ERROR_OK);
  pph_destroy_context(context);

  // reload the context (should be bootstrapping by now)...
  context = pph_reload_context("pph.db");
  ck_assert( context != NULL);

  // create a boostrap account
  error = pph_create_account(context, "bootstrapacc", strlen("bootstrapacc"),
      "bootstrappw", strlen("bootstrappw"), 0);
  ck_assert(error == PPH_ERROR_OK);

  // try to overwrite the account....
  error = pph_create_account(context, "bootstrapacc", strlen("bootstrapacc"),
      "bootstrappw", strlen("bootstrappw"), 0);
  ck_assert(error == PPH_ACCOUNT_EXISTS);


  // login to such account...
  error = pph_check_login(context, "bootstrapacc", strlen("bootstrapacc"),
      "bootstrappw", strlen("bootstrappw"));
  ck_assert(error == PPH_ERROR_OK);
  
  // verify that a wrong account is detected...
  error = pph_check_login(context, "bootstrapacc", strlen("bootstrapacc"),
      "wrongpass", strlen("wrongpass"));
  ck_assert(error == PPH_ACCOUNT_IS_INVALID);

  // unlock the store...
  error = pph_unlock_password_data(context, username_count, usernames, 
      username_lengths, passwords, password_lengths);
  ck_assert_msg(error == PPH_ERROR_OK," EXPECTED PPH_ERROR_OK");

  // verify that we can log in with the new account...
  error = pph_check_login(context, "bootstrapacc", strlen("bootstrapacc"),
      "bootstrappw", strlen("bootstrappw"));
  ck_assert(error == PPH_ERROR_OK);

  // verify that the status of the entry changed to boostrapping.
  account_nodes = context->account_data;
  while(account_nodes != NULL){
    ck_assert(account_nodes->account.entries->share_number != BOOTSTRAP_ACCOUNT);
    account_nodes = account_nodes->next;
  }

  // cleanup, we're done...
  pph_destroy_context(context);

}END_TEST


// simple test case for having the IV used by the AES_CTR mode as the salt value
// instead of NULL ~GA
START_TEST(test_pph_AES_encryption_with_non_null_iv)
{
  // create a context with various shielded accounts
  PPH_ERROR error;
  pph_context *context;
  uint8 threshold = 2; 
  uint8 isolated_check_bits = 0;
  unsigned int i;
  
  // for shielded accounts
  const uint8 shielded_username[] = "username_s1";
  const uint8 shielded_password[] = "password_s1";
  
  // setup the context 
  context = pph_init_context(threshold, isolated_check_bits);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // create shielded account  
  error = pph_create_account(context, shielded_username, strlen(shielded_username),
        shielded_password, strlen(shielded_password), 0);
  ck_assert(error == PPH_ERROR_OK);
  
  // start playing with the _encrypt_digest function using the accounts
  // info we have in the current context
  // we have one account only which is the solo shileded account we 
  // have created earlier 
  pph_account_node *search;
  pph_entry *current_entry;
  search = context->account_data;
  

  // check that we have a valid account before going ahead
  ck_assert(search != NULL && search->account.entries != NULL);
  
  // we have an account
  // retreive the login entry
  current_entry = search->account.entries;
    
  // let us do the following:
  // 1. compute the sharexorhash and compare it with what is stored inside the account
  
  // buffers to compute the salted hash of the current account password  
  uint8 resulting_hash[DIGEST_LENGTH], resulting_hash_2[DIGEST_LENGTH];
  uint8 salted_password[MAX_SALT_LENGTH + MAX_PASSWORD_LENGTH]; 
  uint8 xored_hash[DIGEST_LENGTH], xored_hash_2[DIGEST_LENGTH];
  
  
  // compute the salted hash first
  memcpy(salted_password, current_entry->salt, current_entry->salt_length);
  memcpy(salted_password + current_entry->salt_length, shielded_password, 
      strlen(shielded_password)); 
  _calculate_digest(resulting_hash, salted_password, 
       current_entry->salt_length + strlen(shielded_password));
  
  
  // encrypt the salted hash using the AES_key stored in the context
  _encrypt_digest(xored_hash, resulting_hash, context->AES_key, current_entry->salt);
  
  // now compare the encrypted hash with the one stored in the user account entry
  ck_assert_msg(!memcmp(xored_hash, current_entry->sharexorhash, DIGEST_LENGTH),
      "Invalid stored encrypted salted password hash!");
       
 
  // 2. check that with different IV values the ciphtext for the same
  // plaintext will be different
  // we will work on the same shielded account we have retrieved earlier
  // create any dummy IV for testing
  uint8 dummy_iv[] = "1234567890123456";
  _encrypt_digest(xored_hash_2, resulting_hash, context->AES_key, dummy_iv);   

  // now compare the two encrypted salted hashes
  ck_assert_msg(memcmp(xored_hash, xored_hash_2, DIGEST_LENGTH),
      "Invalid encryption behavior, IV is different and so ciphertext should be!");
  
  
  // 3. check that with the same IV for different plaintexts the ciphertext 
  // should be different
  // we will work on the same shielded account we have retrieved earlier
  _calculate_digest(resulting_hash_2, "CodeTestingIsFun", 
       strlen("CodeTestingIsFun"));
  _encrypt_digest(xored_hash_2, resulting_hash_2, context->AES_key, current_entry->salt);   

  // now compare the two encrypted salted hashes
  ck_assert_msg(memcmp(xored_hash, xored_hash_2, DIGEST_LENGTH),
      "Invalid encryption behavior, plaintext is different and so ciphertext should be!");
      

  // destroy the context
  pph_destroy_context(context);
	
}END_TEST


// test suite definition
Suite * polypasswordhasher_thl_suite(void)
{


  Suite *s = suite_create ("shielded");


  /* no isolated validation with shielded accounts case */
  TCase *tc_non_isolated = tcase_create ("non-isolated");
  tcase_add_test (tc_non_isolated, test_pph_init_context_AES_key);
  tcase_add_test (tc_non_isolated, test_pph_destroy_context_AES_key);
  tcase_add_test (tc_non_isolated, test_pph_create_accounts);
  tcase_add_test (tc_non_isolated, test_create_account_mixed_accounts);
  tcase_add_test (tc_non_isolated, test_check_login_shielded);
  tcase_add_test (tc_non_isolated, test_pph_unlock_password_data);
  tcase_add_test (tc_non_isolated, test_pph_shielded_full_lifecycle);
  tcase_add_test (tc_non_isolated, test_pph_bootstrap_accounts);
  tcase_add_test (tc_non_isolated, test_pph_AES_encryption_with_non_null_iv);
  
  suite_add_tcase (s, tc_non_isolated);

  return s;
}




// suite runner setup
int main (void)
{
  int number_failed;
  Suite *s =  polypasswordhasher_thl_suite();
  SRunner *sr = srunner_create (s);
  srunner_run_all (sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


