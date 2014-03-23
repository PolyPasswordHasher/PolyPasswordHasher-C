PolyPassHash for C  
============

The C implementation for the [PolyPassHash password storage scheme](https://github.com/JustinCappos/PolyPassHash). This repository provides a C library to manage a polypasshash scheme.



What's in here?
=======
Included, you will find an automake-autoconf-libtool project to build the library.

A set of tests is also included. Tests are made for [check](http://check.sourceforge.net). If you have check installed, running make check will run all of the test suites.


Example
=======
```c
  pph_context *context;
  uint8 threshold = 2;    // We set a threshold of minimum shares available
                          //  in order to be able to recover the shares
                          
  uint8 partial_bytes = 2;// Partial bytes refers to the amount of bytes to 
                          //  be used for verification when a context is locked


  // setup the context 
  context = pph_init_context(threshold, partial_bytes);
  
  // add some users, we send the context, username and passsords (with length) and a number
  //  of shares to assign to such user. A user may have more than one share assigned.
  pph_create_account(context, "Alice", strlen("Alice"), "I.love.bob", strlen("I.love.bob"), 1);
  pph_create_account(context, "Bob", strlen("Bob"), "i.secretly.love.eve",strlen(i.secretly.love.eve),1);
  
  // when creating a user with no shares, we get a **thresholdless** account. Thresholdless
  //  accounts have their hash encrypted and cannot unlock a context
  pph_create_account(context,"Eve", strlen("Eve"), "i'm.all.ears", strlen("i'm.all.ears"), 0);
  
  // to check a login we must have an unlocked context, we send the credentials and 
  //  receive an error in return
  if(pph_check_login("alice",strlen("alice"),"I.love.bob",strlen("I.love.bob") == PPH_ERROR_OK){
    printf("welcome alice");
  }else{
    printf("generic error message");
  }
  
  // We can, then store a context to work with it later, have in mind the context will
  //  be stored in a locked state and alice and bob will have to unlock it. 
  pph_store_context(context,"securepasswords");
  
  // we can now safely free the information about our context
  pph_destroy_context(context);
  
  // time goes by... and we want to start working again, with the same information about 
  // alice, bob and eve...
  
  // We reload our context.
  context = pph_reload_context("securepasswords")
  
  // at this point we can still provide a login service, thanks to the partial bytes extension
  if(pph_check_login("alice",strlen("alice"), "i'm.trudy", strlen("i'm.trudy") == PPH_ERROR_OK){
    printf("welcome alice!"); // this won't happen
  }else{
    printf("go away trudy!");
  }
  
  // however, in order to be able to create accounts, we must unlock the vault.
  // for this, we setup an array of username strings and an array of password strings.
  char **usernames = malloc(sizeof(*usernames)*2);
  usernames[0] = strdup("alice");
  usernames[1] = strdup("bob");
  
  char **passwords = malloc(sizeof(*passwords)*2);
  passwords[0] = strdup("I.love.bob");
  passwords[1] = strdup("i.secretly.love.eve");
  
  pph_unlock_password_data(context, 2, usernames, passwords);
  
  // now the data us unlocked. Before unlocking, create account would throw an error. 
  pph_create_account(context, "carl", strlen("carl"), "verysafe", strlen("verysafe"),0)
  
  // we can now check accounts using the full feature also (non-partial bytes)
  if(PPH_ERROR_OK == pph_check_login(context, "carl", strlen("carl"), "verysafe", strlen("verysafe"))){
    printf("welcome back carl"); // this is the expected outcome.
  }else{
    printf("you are not carl");
  }
  
  
  // we should now store the context and free the data before leaving
  pph_store_context(context,"securetpasswords");
  pph_destroy_context(context);

```

API reference
=========
The API is a simple set of functions to aid you in the creation and management of a PolyPassHash scheme. 

* [data structures](#data_structures)
* [functions](#functions)
  * [context management](#context_management)
    * [pph\_init\_context](#pph_init_context)
    * [pph\_destroy\_context](#pph_destroy_context)
    * [pph\_store\_context](#pph_store_context)
    * [pph\_reload\_context](#pph_reload_context)
    * [pph\_unlock\_password\_data](#pph_unlock_password_data)
  * [user\_management](#user_management_functions)
    * [pph\_create\_account](#pph_create_account)
    * [pph\_check\_login](#pph_check_login)

<a name="data_structures"/>
## Data structures
### pph context
The pph context is oriented to facilitate the bookkeeping of changes in the context, it holds the user data, the secret (if available), a reference to the shamir secret sharing data structure, etc. This is a quick overview of the data structure:
```C
  typedef struct _pph_context{
  gfshare_ctx *share_context;    // this is a pointer to the libgfshare engine
  uint8 threshold;               // the threshold set to the libgfshare engine
  uint8 available_shares;        // this is the number of available shares
  uint8 is_unlocked;             // this is a boolean flag indicating whether 
                                 //  the secret is known.
  uint8 *AES_key;                // a randomly generated AES key of SHARE_LENGTH
  uint8 *secret;                 // secret data, generated at initialization
  uint8 partial_bytes;           // partial bytes, if 0, partial verification is
                                 //   disabled
  pph_account_node* account_data;// we will hold a reference to the account
                                 //  data in here
  uint8 next_entry;              // this assigns shares in a round-robin 
                                 //  fashion
}pph_context;
```
### pph\_account and the pph\_entry
These are structures that contain information about user accounts and their
specific shares. As a user of this library, you won't need to address them. 


<a name="functions"/>
## Functions
Functions in the libpolypasshash library are divided in user management or context management. User management functions carry the role of user adding and login check. Context management functions are oriented to the maintenance and operation of the whole polypasshash scheme. 



<a name="context_managemet"/>
### Context management functions.



<a name="pph_init_context"/>
#### pph\_init\_context
Initializes a polypasshash context structure with everything needed in order to work. This is a one-time only initialization, pph_store_context and pph_reload_context will provide a persistent context after initialization.
##### parameters:
  
* Threshold : the minimum number of shares (or username accounts) to provide in order for it to unlock

* patial_bytes : how many bytes are non-obscured by either the AES key or the shamir secret in order to provide partial verification.

##### returns 
An initialized pph_context




<a name="pph_destroy_context"/>
#### pph\_destroy\_context
Safely destroy all of the references in an initialized pph_context. 

###### parameters

* pph_context: the context to destroy.

###### returns
An error code indicating whether the operation was successful or not. 




<a name="pph_store_context"/>
#### pph\_store\_context
Persist the non-sensitive information about a context to disk. Have in mind 
that certain parameters (such as the secret) are not written to disk. In other
words, the context written to disk is stored in a locked state.

###### Parameters

* context : the context to persist

* filename : the name of the file to persist

###### returns
An error code indicating whether the operation was successful or what was the 
reason for failure.





<a name="pph_reload_context"/>
#### pph\_reload\_context
After successfull context-storage, you can reload the context into memory by 
using this function. A reloaded context is locked until the pph_unlock_password_data
function is called. A locked context may not operate for creating accounts, and can
only verify logins if the partial bytes argument provided was non-zero.

###### Parameters

* filename : the filename of the context to reload


###### returns
A locked, but initialized, pph_context. 





<a name="pph_unlock_password_data"/>
#### pph\_unlock\_password\_data.
Provided a sufficient accounts (above the threshold), attempt to unlock the 
context data structure. 

###### parameters

* context : the context to attempt unlocking

* username_count : the number of accounts provided

* usernames : an array of usernames to attempt unlocking

* passwords : an array of passwords correspoding to each username in the same index

###### returns
An error indicating if the attempt was successful or not.





<a name="user_management_functions"/>
### User Management Functions




<a name="pph\_create\_account"/>
#### pph\_create\_account
Given some credentials and an unlocked context, store the user data inside a 
context. 

###### parameters

* context : the context in which the user will be added

* username : the username field, if it already exists, the system will throw an error

* username_length : the length of the username field.

* password : the password for that secific user.

* password_length : the length of the password field

###### returns
An error indicating whether the account could be added, or the cause of failure. 
Too long usernames and passwords will return an error, as well as an already 
existing account. 





<a name="pph_check_login"/>
#### pph\_check\_login
Provided a username and password pair, check if such pair exists within th context.

###### parameters

* context : the context that stores the account information.

* username : the username to look for.

* username_length : the length of the username provided

* password : the password attempt for such username

* password_length : the length of the password field provided. 

###### returns 
An error code indicating if the login attempt was successful.
