#include <iostream>
#include <openssl/evp.h>
#include <vector>
#include <string.h>
#include <string>
#include <iterator>
#include <cstdlib>
#include <sstream>
#include <iomanip>

using namespace std;

/*
 * results checked on
 * https://emn178.github.io/online-tools/sha384.html
*/

// generate new message
void find_text(vector<unsigned char> & text_vector){
    int i = 0;

    bool check = true;
    for(auto i : text_vector){
        if(i != 255){
            check = false;
            break;
        }
    }
    
    if(check)
        text_vector.push_back(0);

    while(true){
        text_vector[i]++;
        if(text_vector[i] == 0)
            i++;
        else
            break;   
    }
}

int main (int argc, char * argv[]){
    // take arguments from command line
    if(argc != 2){
        cerr << "SYNOPSIS\n"
                "\t ./hash NUMBER_OF_ZEROS\n"
                "DESCRIPTION\n"
                "\t Force check SHA384 hash for leading sequence of zeros (big-endian)"
              << endl;
        return 1;
    }

    int number_of_zeros;

    // check if user put only numbers
    try {
        number_of_zeros = stoi(argv[1]);
    } catch(exception const & e){
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    // wrong input
    if(number_of_zeros < 0 || number_of_zeros > 384){
        cerr << "Wrong number of zeros.\n(try number_of_zeros > 0)" << endl;
        return 1;
    }

    vector<unsigned char> text_vector = {0};
    vector<unsigned char> hash_vector;
    unsigned char hash_array[EVP_MAX_MD_SIZE];
    unsigned int hash_array_len;

    string zero_string(number_of_zeros, '0');

    EVP_MD_CTX * context; // structure of context
    const EVP_MD * type; // hash function type
    char hash_function[] = "SHA384"; // set SHA384 hash function

    OpenSSL_add_all_digests(); // initialization of OpenSSL hash functions
    type = EVP_get_digestbyname(hash_function); // using SHA384 hash function

    // trying to use wrong type of hash function
    if(!type){
        cerr << "Hash function \"" << hash_function << "\" does not exist." << endl; 
        return 1;
    }

    // find the message with hash starting with desired zeros
    while(true){
        find_text(text_vector);

        hash_vector.clear();

        // create context for hashing
        context = EVP_MD_CTX_new();
        if(context == NULL)
            return 2;

        // context setup for our hash type
        if(!EVP_DigestInit_ex(context, type, NULL)){
            EVP_MD_CTX_free(context);
            return 3;
        }

        // feed the message in
        if(!EVP_DigestUpdate(context, &text_vector[0], text_vector.size())){
            EVP_MD_CTX_free(context);
            return 4;
        }

        // get the hash
        if(!EVP_DigestFinal_ex(context, hash_array, &hash_array_len)){
            EVP_MD_CTX_free(context);
            return 5;
        }

        // destroy the context
        EVP_MD_CTX_free(context);

        for(unsigned i = 0; i < hash_array_len; i++)
            hash_vector.push_back(hash_array[i]);
        
        // convert hash to binary
        stringstream s;
        for(auto i : hash_vector){
            for (int j = 7; j >= 0; --j)
                s << ((i & (1 << j))? '1' : '0');
        }
        
        // check if the message's hash matches
        if(zero_string == s.str().substr(0, number_of_zeros))
            break;
    }

    // print the result
    for(auto i : text_vector)
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << " ";
    
    for(auto i : hash_vector)
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << endl;

    return 0;
}