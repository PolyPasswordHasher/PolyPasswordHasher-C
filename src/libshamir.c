/*
 * libhsamir.c module:
 *  this lightweight module is a supporting library for the polypasshash
 *  implementation in C.
 *
 *  This library includes the function definitions for interfaces as 
 *  creating a new shamir secret and generating shares.
 * 
 * @author  Santiago Torres
 * @date    03/06/2014
 * @license MIT
 */
#include "libshamir.h"


/* generate_shamir_secret function:
 *
 * populates a SHAMIR_SECRET function when provided the correct arguments
 *
 * @args
 *  SHAMIR_SECRET *secret will point to the populated shamir secret after
 *    this function is ran
 *
 *  unsighed int threshold is the threshold for this specific shamir secret
 *
 *  uint8 *data a datastream for the secret, the user can provide a string
 *    if so desired
 *
 *  unsigned int data_legth the lenght of the secret data, since data cannot
 *    be a \0-terminated string.
 *
 * @returns
 *  SHAMIR_ERROR an error code indicating what went wrong, if we manage to find
 *  out
 */
SHAMIR_ERROR generate_shamir_secret(SHAMIR_SECRET *secret,
    unsigned int threshold, uint8 *secret_data, unsigned int data_length){
  return ERROR_OK;
}


/* calculate_share function:
 *
 * populates a SHAMIR_SHARE structure based on the shamir_secret provided and
 * the share number
 *
 * @args
 *  SHAMIR_SECRET *secret is the secret from where the share will be calculated
 *
 *  SHAMIR_SHARE *share will be populated at the end of the function
 *
 *  uint8 share_number is the share to calculate
 *
 * @returns
 *  SHAMIR_ERROR indicating what went wrong or ERROR_OK if everything seems to 
 *  be fine
 */
SHAMIR_ERROR calculate_share(SHAMIR_SECRET *secret, SHAMIR_SHARE *share,
    uint8 share_number){
  return ERROR_UNKNOWN;
}


/* is_valid_share function:
 *
 * based on the provided SHAMIR_SECRET, tell if the provided share is correct
 * and belongs to that secret.
 *
 * @args
 *  SHAMIR_SECRET *secret the secret to use
 *  SHAMIR_SHARE *share the share to check
 *
 * @returns
 *  SHAMIR_ERROR with ERROR_OK if the share belongs and ERROR_INCORRECT_SHARE
 *  otherwise
 */
SHAMIR_ERROR is_valid_share(SHAMIR_SECRET *secret, SHAMIR_SHARE *share){
  return ERROR_UNKNOWN;
}

// internal functions
// these functions are not mean to be used outside this library's scope
SHAMIR_ERROR full_lagrange(unsigned int *x, unsigned int *xs,
    unsigned int length, uint8 *result, unsigned int result_length){
  return ERROR_UNKNOWN;
}

int * add_polynomial(int *a, int *b, unsigned int length){
  return ERROR_UNKNOWN;
}
int * substract_polynomial(int *a, int *b, unsigned int length){
  return ERROR_UNKNOWN;
}
int * multiply_polynomial(int *a, int *b, unsigned int length_a, 
    unsigned int length_b){
  return ERROR_UNKNOWN;
}
int * divide_polynomial(int *a, int *b, unsigned int length){
  return ERROR_UNKNOWN;
}

int f(int x, int *coefficients, unsigned int coefficient_length){
  return ERROR_UNKNOWN;
}

