/*
 * fs_crypt.h
 *
 * File server encryption routines.
 */

#ifndef _FS_CRYPT_H_
#define _FS_CRYPT_H_

/*
 * Encrypt data using AES encryption, using the null-terminated string in
 * password as the encryption key.  The block of data to be encrypted is
 * pointed to by buf_decrypt and is of size size_decrypt.  fs_encrypt stores
 * the encrypted data in buf_encrypt (which is allocated by the caller).  The
 * encrypted data is guaranteed to be no larger than 2 * size_decrypt + 64
 * bytes.  fs_encrypt returns the size of the encrypted data, or -1 upon failure.
 *
 * fs_encrypt is thread safe.
 */
int fs_encrypt(const char* password, const void* buf_decrypt,
                        const unsigned int size_decrypt, void* buf_encrypt);

/*
 * Decrypt data using AES encryption, using the null-terminated string in
 * password as the decryption key.  The block of data to be decrypted is
 * pointed to by buf_encrypt and is of size size_encrypt.  fs_decrypt
 * stores the decrypted data in buf_decrypt (which is allocated by the caller).
 * The decrypted data is guaranteed to be no larger than the encrypted
 * data. fs_decrypt returns the size of the decrypted data, or -1 upon failure.
 *
 * fs_decrypt is thread safe.
 */
int fs_decrypt(const char* password, const void* buf_encrypt,
                        const unsigned int size_encrypt, void* buf_decrypt);

#endif /* _FS_CRYPT_H_ */
