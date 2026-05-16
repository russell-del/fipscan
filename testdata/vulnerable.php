<?php

function bad_md5($data) {
    return md5($data);
}

function bad_sha1($data) {
    return sha1($data);
}

function bad_md5_hash($data) {
    return hash('md5', $data);
}

function bad_des($plaintext, $key) {
    return openssl_encrypt($plaintext, 'des-cbc', $key);
}

function bad_3des($plaintext, $key) {
    return openssl_encrypt($plaintext, 'des-ede3-cbc', $key);
}

function bad_rc4($plaintext, $key) {
    return openssl_encrypt($plaintext, 'rc4', $key);
}

function legacy_mcrypt($plaintext, $key) {
    $iv = mcrypt_create_iv(8, MCRYPT_DES);
    return mcrypt_encrypt(MCRYPT_DES, $key, $plaintext, MCRYPT_MODE_CBC, $iv);
}
