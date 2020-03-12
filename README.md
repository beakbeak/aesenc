# aesenc/aesdec

`aesenc` is a command-line utility that reads a stream of data from standard
input and encrypts it to standard output using AES-256-CBC via OpenSSL. The AES
key is generated at run time and encrypted with a public key in PEM format.

`aesdec` reads a stream of encrypted data from standard input and decrypts it to
standard output.

## Example usage

Generate an RSA key pair using the `openssl` command-line utility:

    $ openssl genrsa -out private.pem 4096
    Generating RSA private key, 4096 bit long modulus (2 primes)
    .............................++++
    .................++++
    e is 65537 (0x010001)

    $ openssl rsa -in private.pem -pubout -out public.pem
    writing RSA key

Pass the public key to `aesenc` and the private key to `aesdec`:

    $ ./aesenc
    usage: aesenc <public key>

    $ ./aesdec
    usage: aesdec <private key>

    $ echo 'Hello, world!' | ./aesenc public.pem > encrypted.txt
    $ ./aesdec private.pem < encrypted.txt
    Hello, world!
