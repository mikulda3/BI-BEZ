#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <iostream>
#include <string>
#include <exception>

using namespace std;
 
bool encrypt(FILE *& input_file, FILE *& output_file, const EVP_CIPHER *& cipher,
             EVP_CIPHER_CTX * ctx){
    int textLength = 0;
    unsigned char buffer_in[1024];
    unsigned char buffer_out[1024 + EVP_MAX_BLOCK_LENGTH];
    unsigned int bytes = 0;
    unsigned int copy_size = 0;

    // encrypt the file
    while((copy_size = fread(buffer_in, 1, 1024, input_file))){

        // encrypt
        if(EVP_SealUpdate(ctx, buffer_out, &textLength, buffer_in,
                          copy_size) != 1)
            return true;

        bytes = fwrite(buffer_out, 1, textLength, output_file);

        // write the cipher
        if(bytes != (unsigned int)textLength)
            return true;
    } 

    // encrypt final block
    if(EVP_SealFinal(ctx, buffer_out, &textLength) != 1)
        return true;

    bytes = fwrite(buffer_out, 1, textLength, output_file);

    // write the last block
    if(bytes != (unsigned int)textLength)
        return true;

    return false;
}

bool decrypt(FILE *& input_file, FILE *& output_file, const EVP_CIPHER *& cipher,
             EVP_CIPHER_CTX * ctx){
    int text_length = 0;
    unsigned char buffer_in[1024];
    unsigned char buffer_out[1024 + EVP_MAX_BLOCK_LENGTH];
    unsigned int bytes = 0;
    unsigned int copy_size = 0;

    // decrypt the file
    while((copy_size = fread(buffer_in, 1, 1024, input_file))){

        if(EVP_OpenUpdate(ctx, buffer_out, &text_length, buffer_in,
                          copy_size) != 1)
            return true;

        bytes = fwrite(buffer_out, 1, text_length, output_file);

        // write the cipher
        if(bytes != (unsigned int)text_length)
            return true;
    } 

    // decrypt the final block
    if(EVP_OpenFinal(ctx, buffer_out, &text_length) != 1)
        return true;

    bytes = fwrite(buffer_out, 1, text_length, output_file);

    // write the last block
    if(bytes != (unsigned int)text_length)
        return true;    

    return false;
}

bool write_header(FILE * output_file, const unsigned char * my_ek, 
                  const int my_ekl, const unsigned char * iv, const int ivl, 
                  string & cipher_type){
    int CTL = cipher_type.length();

    // write the header 
    if(fwrite(&CTL, sizeof(int), 1, output_file) != 1)
        return true;

    if(fwrite(cipher_type.c_str(), 1, cipher_type.length(),
              output_file) != cipher_type.length())
        return true;

    // ekl
    if(fwrite(&my_ekl, sizeof(int), 1, output_file) != 1)
        return true;

    // ek
    if(fwrite(my_ek, sizeof(my_ek[0]), my_ekl, output_file) != (size_t)my_ekl)
        return true;

    // ivl
    if(fwrite(&ivl, sizeof(int), 1, output_file) != 1)
        return true;

    // iv
    if(fwrite(iv, sizeof(iv[0]), ivl, output_file) != (size_t)ivl)
        return true;

    return false;
}

bool read_header(FILE * input_file, unsigned char *& my_ek, int & my_ekl,
                 unsigned char * iv, string & cipher_type){

    int CTL;
    
    // read info header
    if(fread(&CTL, sizeof(int), 1, input_file) != 1)
        return true;

    // ctl too long
    if(CTL > 100)
        return true;

    char * buffer = (char*)malloc(sizeof(char) * CTL + 7);
    if( fread( buffer, 1, CTL, input_file ) != (size_t)CTL )
        return true;

    buffer[CTL] = '\0';
    cipher_type = buffer;
    free(buffer);
    
    // failed to read ekl
    if( fread( &my_ekl, sizeof(int), 1, input_file ) != 1 )
        return true;

    // wrong length
    if( my_ekl > 1024 )
        return true;

    my_ek = (unsigned char*)malloc(sizeof(unsigned char) * my_ekl);
    // wrong size
    if(fread(my_ek, 1, my_ekl, input_file) != (size_t)my_ekl)
        return true;

    int ivl;
    // wrong ivl
    if(fread(&ivl, sizeof(int), 1, input_file) != 1)
        return true;
    
    // wrong length
    if(ivl > EVP_MAX_IV_LENGTH)
        return true;

    // wrong iv
    if(fread(iv, sizeof(unsigned char), ivl, input_file) != (size_t)ivl)
        return true;
    
    return false;
}

bool init_cipher(const EVP_CIPHER *& cipher, EVP_CIPHER_CTX *& ctx,
                string & cipher_type){
    OpenSSL_add_all_ciphers();

   string my_cipher = cipher_type.c_str();
    if(my_cipher == "aes-cbc")
        cipher = EVP_des_cbc();  
    else if(my_cipher == "aes-ecb")
        cipher = EVP_des_ecb();
    else
        cipher = EVP_get_cipherbyname(my_cipher.c_str());

    // unknown cipher
    if(!cipher)
        return true;
    
    ctx = EVP_CIPHER_CTX_new();

    // creating context failed
    if(!ctx)
        return true;

    return false;
}

int encrypting(EVP_PKEY *& p_key, FILE * input_file, FILE * output_file){
    unsigned char iv[EVP_MAX_IV_LENGTH];
    string cipher_type = "aes-cbc";
    const EVP_CIPHER * cipher;
    EVP_CIPHER_CTX * ctx;
    
    unsigned char * my_ek = (unsigned char*)malloc(EVP_PKEY_size(p_key));
    int my_ekl;

    if(init_cipher(cipher, ctx, cipher_type)){
        cerr << "Failed to initialize the cipher!" << endl;
        EVP_CIPHER_CTX_free(ctx); 
        free(my_ek);
        EVP_PKEY_free(p_key);
        return 1;
    }

    if(EVP_SealInit(ctx, cipher, &my_ek, &my_ekl, iv, &p_key, 1) != 1){
        cerr << "Failed to initialize the cipher!" << endl;
        EVP_CIPHER_CTX_free(ctx); 
        free(my_ek);
        EVP_PKEY_free(p_key);
        return 1;
    }
    
    int ivl = EVP_CIPHER_iv_length(cipher);

    if(write_header(output_file, my_ek, my_ekl, iv, ivl, cipher_type)){
        cerr << "Failed to write to the header!" << endl;
        EVP_CIPHER_CTX_free(ctx); 
        free(my_ek);
        EVP_PKEY_free(p_key);
        return 1;
    }

    if(encrypt(input_file, output_file, cipher, ctx)){
        cerr << "Failed to decrypt!" << endl;
        EVP_CIPHER_CTX_free(ctx); 
        free(my_ek);
        EVP_PKEY_free(p_key);
        return 1;
    }

    EVP_CIPHER_CTX_free(ctx); 
    free(my_ek);
    EVP_PKEY_free(p_key);

    return 0;
}

int decrypting(EVP_PKEY *& p_key, FILE * input_file, FILE * output_file){
    unsigned char iv[EVP_MAX_IV_LENGTH];
    string cipher_type;
    const EVP_CIPHER * cipher;
    EVP_CIPHER_CTX * ctx;
    
    unsigned char * my_ek = nullptr;
    int my_ekl;

    if(read_header(input_file, my_ek, my_ekl, iv, cipher_type)){
        cerr << "Failed to read the header!" << endl;
        EVP_CIPHER_CTX_free(ctx); 
        free(my_ek);
        EVP_PKEY_free(p_key);
        return 1;
    }

    if(init_cipher(cipher, ctx, cipher_type)){
        cerr << "Failed to initialize the cipher!" << endl;
        EVP_CIPHER_CTX_free(ctx); 
        free(my_ek);
        EVP_PKEY_free(p_key);
        return 1;
    }

    if(EVP_OpenInit(ctx, cipher, my_ek, my_ekl, iv, p_key ) != 1){
        cerr << "Failed to initialize the cipher. Possibly wrong key!" << endl;
        EVP_CIPHER_CTX_free(ctx); 
        free(my_ek);
        EVP_PKEY_free(p_key);
        return 1;
    }

    if(decrypt(input_file, output_file, cipher, ctx)){
        cerr << "Failed to decrypt!" << endl;
        EVP_CIPHER_CTX_free(ctx); 
        free(my_ek);
        EVP_PKEY_free(p_key);
        return 1;
    }

    EVP_CIPHER_CTX_free(ctx); 
    free(my_ek);
    EVP_PKEY_free(p_key);

    return 0;
}

int main(int argc, char ** argv){

    bool encrypt;

    // check and parse aguments
    if(argc != 5  || (string(argv[1]) != "-e" && string(argv[1]) != "-d")){
        cerr << "SYNOPSIS\n"
                "\t ./task3 -e/-d KEY_FILE FILE_NAME OUT_FILE\n"
              << endl;
        return 1;
    }

    if(string(argv[1]) != "-d" && string(argv[1]) != "-e"){
        cerr << "Failed to recognize encrypt/decrypt flag!" << endl;
        return 1;
    }

    if(string(argv[1]) == "-d")
        encrypt = false;
    
    if(string(argv[1]) == "-e")
        encrypt = true;

    if(encrypt)
        if(RAND_load_file("/dev/random", 32) != 32){
            cerr << "Cannot seed the random generator!" << endl;
            return 1;
        }

    string key_name(argv[2]);
    string input_file_name(argv[3]);
    string output_file_name(argv[4]);

    FILE * input_file;
    FILE * key_file;
    FILE * output_file;


    EVP_PKEY * p_key;

    // open and create files
    if(!(input_file = fopen(input_file_name.c_str(),"rb"))){
        cerr << "Failed managing files" << endl;
        return 1;
    }
    if(!(key_file = fopen(key_name.c_str(),"rb"))){
            if(fclose(input_file)){
                cerr << "Failed managing files" << endl;
                return 1;
            }
        cerr << "Failed managing files.a" << endl;
        return 1;
    }

    if(!(output_file = fopen(output_file_name.c_str(),"wb"))){
        if(fclose(input_file)){
            cerr << "Failed managing files." << endl;
            return 1;
        }
        if(fclose(key_file)){
            cerr << "Failed managing files." << endl;
            return 1;
        }
        cerr << "Failed managing files." << endl;
        return 1;
    }


    // read private/public key
    if(encrypt){
        if(!(p_key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL))){
            cerr << "Failed reading public key!" << endl;
            return 1;
        }
    } else {
        if(!(p_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL))){
            cerr << "Failed reading private key! " << endl;
            return 1;
        }
    }

    // perform desired operation
    if(encrypt){
        if(encrypting(p_key, input_file, output_file))
            return 1;
    } else {
        if(decrypting(p_key, input_file, output_file))
            return 1;
    }

    // close files
    if(fclose(input_file) || fclose(key_file) || fclose(output_file)){
        cerr << "Failed closing files!" << endl;
        return 1;
    }

    return 0;
}