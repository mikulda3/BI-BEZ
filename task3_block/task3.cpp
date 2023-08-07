/* autor: David Mikulka
 * ECB vs CBC:
 * U ECB se pouziva inicializacni vektor na kazdy blok, proto to neni tak 
 * bezpecne. Je to dobre videt pri zasifrovani nejakeho obrazku, kde je pak 
 * jasne videt puvodni obrazek, akorat ma jine barvy. Moc to informace tedy
 * nezasifruje a da se to lehce desifrovat.
 * Oproti tomu CBC vyuziva predchozi blok k sifrovani dalsimu, tedy informace
 * je mnohem lepe zasifrovana, coz je opet videt ze zasifrovaneho obrazku,
 * ze ktereho neni nic poznat.
**/

#include <cstdlib>
#include <openssl/evp.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using namespace std;

int main(int argc, char * argv[]){
    unsigned char key[EVP_MAX_KEY_LENGTH] = "my secret key";  // key for cipher
    unsigned char iv[EVP_MAX_IV_LENGTH] = "initial. vector";  // IV
    const EVP_CIPHER * cipher;

    // check input
    if(argc != 4 || (string(argv[1]) != "-e" && string(argv[1]) != "-d") 
       || (string(argv[2]) != "ecb" && string(argv[2]) != "cbc")){
        cerr << "SYNOPSIS\n"
                "\t ./task3 -e/-d ecb/cbc FILE_NAME\n"
                "DESCRIPTION\n"
                "\t Cipher or decipher desired file using ECB or CBC cipher."
              << endl;
        return 1;
    }

    // check input file
    string file_name = string(argv[3]);
    ifstream in_file(file_name, ios::binary);
    if(file_name.substr(file_name.find_last_of(".") + 1) != "tga"){
        cerr << "Wrong input file format. Input file must be in .tga format." << endl;
        return 1;
    }

    if(!in_file.is_open()){
        cerr << "Cannot open given file." << endl;
        return 1;
    }

    // determine output file name and cipher type
    string output_file_name;
    char cipher_name[12];
    bool encrypt = true;
    if(string(argv[1]) == "-d"){
        output_file_name = "_dec.tga";
        encrypt = false;
    }
    if(string(argv[2]) == "cbc"){
        if(string(argv[1]) == "-e")
            output_file_name = "_cbc.tga";
        strcpy(cipher_name, "AES-128-CBC");
    } else if(string(argv[2]) == "ecb"){
        if(string(argv[1]) == "-e")
            output_file_name = "_ecb.tga";
        strcpy(cipher_name, "AES-128-ECB");
    }

    // choose cipher
    OpenSSL_add_all_ciphers();
    cipher = EVP_get_cipherbyname(cipher_name);
    if(!cipher){
        cerr << "Cipher " << cipher_name << " does not exist." << endl;
        in_file.close();
        return 1;
    }

    // read and store the header
    char header[18];
    for(int i = 0; i < 18; i++){
        header[i] = in_file.get();
        if(in_file.fail() || in_file.eof()){
            cerr << "Wrong header of input file." << endl;
            in_file.close();
            return 1;
        }
    }
    
    int image_id = (int)header[0];

    int color_map = (int)header[7] * (int)( (header[6] << 8) | (header[5]) );
    color_map /= 8;
    
    if(image_id < 0 || color_map < 0){
        cerr << "Wrong header of input file." << endl;
        in_file.close();
        return 1;
    }

    int skip = image_id + color_map;

    // open output file and write the header into it
    string out_file_name = file_name.erase(file_name.size() - 4, file_name.size())
                 + output_file_name;
    ofstream out_file(out_file_name, ios::binary);
    for(int i = 0; i < 18; i++){
        out_file << header[i];
        if(in_file.fail()){
            cerr << "Wrong header of input file." << endl;
            in_file.close();
            remove(out_file_name.c_str()); 
            return 1;
        }
    }
    unsigned char buffer[1];
    for(int i = 0; i < skip; i++){
        buffer[0] = in_file.get();
        if(in_file.fail() || in_file.eof()){
            cerr << "Wrong header of input file." << endl;
            in_file.close();
            remove(out_file_name.c_str()); 
            return 1;
        }
        out_file << buffer[0];
    }

    // create context
    EVP_CIPHER_CTX * ctx; // context structure
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL)
        return 2;
    
    // set context for encrypting/decrypting
    if(encrypt){
        if(!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)){
            in_file.close();
            remove(out_file_name.c_str()); 
            EVP_CIPHER_CTX_free(ctx);   
            return 3;
        }
    } else {
        if(!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)){
            in_file.close();
            remove(out_file_name.c_str()); 
            EVP_CIPHER_CTX_free(ctx);   
            return 6;
        }
    }

    // perform desired actions
    int otLength = 0, stLength = 0, tmpLength = 0;
    unsigned char input_text[1024];
    unsigned char output_text[1024 + EVP_MAX_BLOCK_LENGTH];
    while(in_file){
        stLength = 0, tmpLength = 0;

        // read block from file
        if(!in_file.read(reinterpret_cast<char*>(input_text), 1024)){
            if(!in_file.eof()){
                cerr << "Cannot read picture data." << endl;
                in_file.close();
                out_file.close();
                remove(out_file_name.c_str()); 
                return 1;
            }
        }
            
        otLength = in_file.gcount();
        if(!otLength)
            break;

        // encrypting
        if(encrypt){
            if(!EVP_EncryptUpdate(ctx, output_text, &tmpLength, input_text, otLength)){
                in_file.close();
                remove(out_file_name.c_str());  
                EVP_CIPHER_CTX_free(ctx);   
                return 4;
            }
            stLength += tmpLength;
            for(int i = 0; i < stLength; i++)
                out_file << output_text[i];
        } else { // decrypting
            if(!EVP_DecryptUpdate(ctx, output_text, &tmpLength,  input_text, otLength)){
                in_file.close();
                remove(out_file_name.c_str()); 
                EVP_CIPHER_CTX_free(ctx);
                return 7;
            }
            stLength += tmpLength;
            for(int i = 0; i < stLength; i++)
                out_file << output_text[i];
        }
    }
    
    // get the remaining
    if(encrypt){
        if(!EVP_EncryptFinal_ex(ctx, output_text, &tmpLength)){
            in_file.close();
            remove(out_file_name.c_str()); 
            EVP_CIPHER_CTX_free(ctx);
            return 5;
        }   
        for(int i = 0; i < tmpLength; i++)
            out_file << output_text[i];
    } else {
        if(!EVP_DecryptFinal_ex(ctx, output_text, &tmpLength)){
            in_file.close();
            remove(out_file_name.c_str());
            EVP_CIPHER_CTX_free(ctx);
            return 8;
        }
        for(int i = 0; i < tmpLength; i++)
            out_file << output_text[i];
    }
    
    // free context
    EVP_CIPHER_CTX_free(ctx);
    in_file.close();
    out_file.close();

    return 0;
}
