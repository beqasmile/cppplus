#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <sys/types.h>
#include <security/pam_appl.h>
#include <unistd.h>

// To build this:
// g++ test.cpp -lpam -o test

// if pam header files missing try:
// sudo apt install libpam0g-dev

struct pam_response *reply;

pid_t getpid(void);

//function used to get user input
int function_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
  *resp = reply;
  return PAM_SUCCESS;
}

int main(int argc, char** argv)
{
  if(argc != 2) {
      fprintf(stderr, "Usage: check_user <username>\n");
      exit(1);
  }
  const char *username;
  username = argv[1];

   pid_t pid = getpid();
    printf("pid: %lun", pid);

  const struct pam_conv local_conversation = { function_conversation, NULL };
  pam_handle_t *local_auth_handle = NULL; // this gets set by pam_start

  int retval;

  // local_auth_handle gets set based on the service
  retval = pam_start("common-auth", username, &local_conversation, &local_auth_handle);

  if (retval != PAM_SUCCESS)
  {
    std::cout << "pam_start returned " << retval << std::endl;
    exit(retval);
  }

  reply = (struct pam_response *)malloc(sizeof(struct pam_response));

  // *** Get the password by any method, or maybe it was passed into this function.
  reply[0].resp = getpass("Password: ");
  reply[0].resp_retcode = 0;

  retval = pam_authenticate(local_auth_handle, 0);

  if (retval != PAM_SUCCESS)
  {
    if (retval == PAM_AUTH_ERR)
    {
      std::cout << "Authentication failure." << std::endl;
    }
    else
    {
      std::cout << "pam_authenticate returned " << retval << std::endl;
    }
    exit(retval);
  }

  std::cout << "Authenticated." << std::endl;

  retval = pam_end(local_auth_handle, retval);

  if (retval != PAM_SUCCESS)
  {
    std::cout << "pam_end returned " << retval << std::endl;
    exit(retval);
  }

  return retval;
}