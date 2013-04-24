/*
Copyright 2013 Philip Lafleur

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <errno.h>
#include <stdio.h>
#include <malloc.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#define INBUF_SIZE 4096
#define MAX_ENCRYPTED_KEY_LENGTH 32768

int
main (int    argc,
      char** argv)
{
  int            return_code = 1;
  EVP_CIPHER_CTX ctx;
  EVP_PKEY*      key;
  unsigned char* encrypted_key;
  unsigned       encrypted_key_length = 0;
  unsigned char* iv;
  int            iv_length = 0;
  unsigned char  byte = 0;
  unsigned char* inbuf;
  unsigned char* outbuf;
  FILE*          binary_stdout;
  FILE*          binary_stdin;

  if (argc < 2)
  {
    fprintf (stderr, "%s", "usage: aesdec <privkey>\n");
    return 1;
  }

  {
    FILE* keyfile = fopen (argv[1], "r");
    if (! keyfile)
    {
      perror ("error: failed to open key file: ");
      return 1;
    }

    key = PEM_read_PrivateKey (keyfile, NULL, NULL, NULL);
    fclose (keyfile);

    if (! key)
    {
      fprintf (stderr, "%s", "error: failed to process key file\n");
      return 1;
    }
  }

  iv_length = EVP_CIPHER_iv_length (EVP_aes_256_cbc ());
  iv = malloc (iv_length);
  if (! iv)
  {
    perror ("error: malloc: ");
    goto error1;
  }

  inbuf = malloc (INBUF_SIZE);
  if (! inbuf)
  {
    perror ("error: malloc: ");
    goto error2;
  }

  outbuf = malloc (INBUF_SIZE + EVP_CIPHER_block_size (EVP_aes_256_cbc ()));
  if (! outbuf)
  {
    perror ("error: malloc: ");
    goto error3;
  }

  binary_stdout = fdopen (STDOUT_FILENO, "wb");
  if (! binary_stdout)
  {
    perror ("error: failed to reopen stdout as binary: ");
    goto error4;
  }

  binary_stdin = fdopen (STDIN_FILENO, "rb");
  if (! binary_stdin)
  {
    perror ("error: failed to reopen stdin as binary: ");
    goto error5;
  }

  if (fread (&byte, 1, 1, binary_stdin) != 1)
  {
    perror ("error: fread: ");
    goto error5;
  }
  if (byte != 0)
  {
    fprintf (stderr, "%s", "error: invalid file version");
    goto error5;
  }

  if (fread (iv, 1, iv_length, binary_stdin) != iv_length)
  {
    perror ("error: fread: ");
    goto error5;
  }

  if (fread (&byte, 1, 1, binary_stdin) != 1)
  {
    perror ("error: fread: ");
    goto error5;
  }
  encrypted_key_length = byte;

  if (fread (&byte, 1, 1, binary_stdin) != 1)
  {
    perror ("error: fread: ");
    goto error5;
  }
  encrypted_key_length |= (((unsigned) byte) << 8);

  if (encrypted_key_length > MAX_ENCRYPTED_KEY_LENGTH)
  {
    fprintf (stderr, "%s", "error: invalid key length");
    goto error5;
  }

  encrypted_key = malloc (encrypted_key_length);
  if (! encrypted_key)
  {
    perror ("error: malloc: ");
    goto error6;
  }

  if (fread (encrypted_key, 1, encrypted_key_length, binary_stdin)
      != encrypted_key_length)
  {
    perror ("error: fread: ");
    goto error7;
  }

  if (EVP_OpenInit (
          &ctx, EVP_aes_256_cbc (), encrypted_key, encrypted_key_length,
          iv, key)
      == 0)
  {
    fprintf (stderr, "%s", "error: EVP_OpenInit failed");
    goto error7;
  }

  for (;;)
  {
    int bytes_in  = 0,
        bytes_out = 0;

    bytes_in = fread (inbuf, 1, INBUF_SIZE, binary_stdin);
    if (bytes_in == 0)
    {
      if (EVP_OpenFinal (&ctx, outbuf, &bytes_out) == 0)
      {
        fprintf (stderr, "%s", "error: EVP_OpenFinal failed");
        goto error8;
      }
    }
    else if (EVP_OpenUpdate (&ctx, outbuf, &bytes_out, inbuf, bytes_in) == 0)
    {
      fprintf (stderr, "%s", "error: EVP_OpenError failed");
      goto error8;
    }

    if (bytes_out > 0)
      fwrite (outbuf, 1, bytes_out, binary_stdout);
    if (bytes_in == 0)
      break;
  }

  return_code = 0;

error8:
  EVP_CIPHER_CTX_cleanup (&ctx);
error7:
  free (encrypted_key);
error6:
  /*fclose (binary_stdin);*/
error5:
  /*fclose (binary_stdout);*/
error4:
  free (outbuf);
error3:
  free (inbuf);
error2:
  free (iv);
error1:
  EVP_PKEY_free (key);
  return return_code;
}
