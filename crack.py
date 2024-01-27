import hashlib
import base64
import argparse


def salt_hash(password: str):
    _, _, salt, encrypted_password = password.split('$')
    return salt, encrypted_password


def calculate_hash(salt: str, password: str):
    m = hashlib.sha1()
    m.update(salt.encode('utf-8'))
    m.update(password.encode('utf-8'))
    encrypted_password = m.digest()

    encrypted_base64 = base64.urlsafe_b64encode(encrypted_password).decode('utf-8').replace('+', '.')
    
    # Finally remove any padding. Apache Ofbiz uses Base64.encodeBase64URLSafeString 
    # from the apache.commons.codec.binary package:
    # https://github.com/apache/ofbiz-framework/blob/a07c44f51660f091feec66723017b3366b243b11/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java#L164
    # This base64 encoding _DOES NOT ADD PADDING_:
    # https://commons.apache.org/proper/commons-codec/apidocs/org/apache/commons/codec/binary/Base64.html#encodeBase64URLSafeString-byte:A-
    encrypted_base64_no_padding = encrypted_base64.rstrip('=')

    return encrypted_base64_no_padding


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--password', help='The password to be cracked. Format $sha$salt$hash')
    parser.add_argument('--wordlist', help='Wordlist to use for cracking. Like rockyou.txt')
    args = parser.parse_args()

    # Get salt and target hash
    salt, target_hash = salt_hash(args.password)

    with open(args.wordlist, 'r', encoding='latin-1') as rockyou:
        for line in rockyou:

            # Remove any newlines
            guess = line.strip()

            # Calculate the hash with the salt
            calculated_hash = calculate_hash(salt, guess)

            if calculated_hash == target_hash:
                print(f'{args.password}:{guess}')
                exit(0)
            
    # No hits
    print('Could not find a match')

