#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unordered_set>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/utility.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <bitset>
#include <iomanip>
#include <random>
#include <unordered_map>
#include <iostream>
using namespace std;
#include <fstream>
#include <istream>
#include <boost/asio.hpp>
namespace asio = boost::asio;
using asio::ip::tcp;

typedef unsigned char uc;
bool no_keyword = 0;
uc counter = 1; //for store func
uc counter2 = 1; //for restore
const int HEADER_SIZE = 10;
typedef unsigned char AES_e[16];
bool is_new_packet = 1;
int payload_len = 0;
typedef std::pair<std::bitset<80>, std::bitset<129>> MyPair;



#pragma pack(push,1)
typedef struct Packet {
    std::vector<uint8_t> header; // 10바이트
    std::vector<uint8_t> payload; // 1024 바이트
}Packet;
#pragma pack(pop)

template <typename Archive>
void serialize(Archive& ar, Packet& packet, const unsigned int version) {
    ar& packet.header;
    ar& packet.payload;
}
void PrintMenu() {
    cout << endl;
    cout << "====================Menu====================\n\n" << endl;
    cout << "1. Press 1 and Enter to upload your Tset." << endl;
    cout << "2. Press 2 and Enter to upload your file." << endl;
    cout << "3. Press 3 and Enter to download file with the keyword you want." << endl;
    cout << "4. Press 4 and Enter to disconnect from the server.\n\n" << endl;
    cout << "============================================\n";
}
void PrintUser() {
    cout << "====================Hello===================\n\n";
    cout << "          This is Security Cloud Service...\n";
    cout << "          Please Press the Button and Enter\n\n";
    cout << "          1. Register (I'm a new client!)\n";
    cout << "          2. Log In\n\n";
    cout << "============================================\n";
    cout << "your choice:";
}
uc* Encrypt_word(string word) {

    uc buff[16] = { 0 };
    //uc ci_len = 16;
    uc* c_i = new uc[16];
    uc x_i[16] = { 0 };
    uc s_i[8] = { 0 };
    uc hash_input_k1_i[17] = { 0 };
    uc hash_input_k2_Li[24] = { 0 };
    uc kk_i[32] = { 0 };
    uc hash_input_kk_i_s_i[40] = { 0 };
    uc T_i[16] = { 0 };

    string filename = "k0k1k2.txt";
    ifstream _kf;
    _kf.open(filename);

    char k1_char[33] = { 0 };
    char k2_char[33] = { 0 };
    char k0_char[33] = { 0 };
    if (_kf.is_open()) {
        _kf.read(k0_char, 32);
        _kf.seekg(34, std::ios::beg);
        _kf.read(k1_char, 32);
        _kf.seekg(68, std::ios::beg);
        _kf.read(k2_char, 32);
    }
    _kf.close();
    uc k0[16] = { 0 };
    uc k1[16] = { 0 };
    uc k2[16] = { 0 };

    for (int i = 0; i < 16; i++) {
        sscanf(k0_char + (i * 2), "%2hhx", &k0[i]);
        sscanf(k1_char + (i * 2), "%2hhx", &k1[i]);
        sscanf(k2_char + (i * 2), "%2hhx", &k2[i]);
    } //k1, k2을 불러와서 uc type에 저장
    

    for (int i = 0; i < 16; i++) {
        if (i < strlen(word.c_str()))
            buff[i] = (unsigned char)word.c_str()[i];
        else
            buff[i] = 0;
    }
    int outLen = 16, inBuf = 16;
    EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(aes_ctx);
    EVP_CIPHER_CTX_set_padding(aes_ctx, false);
    EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_ecb(), 0, k0, 0);
    EVP_EncryptUpdate(aes_ctx, x_i, &outLen, buff, inBuf);
    EVP_CIPHER_CTX_cleanup(aes_ctx);
    printf("x_i: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", x_i[i]);
    }
    printf("\n");  //x_i 출력
    EVP_CIPHER_CTX_free(aes_ctx);

    //$$$$$$$$$   2.s_i 만들기 $$$$$$$$$$$$$$
    for (int i = 0; i < 17; i++) {
        if (i == 16) {
            hash_input_k1_i[16] = counter;
            break;
        }
        hash_input_k1_i[i] = k1[i];
    }   //hash_input_k1_i변수 저장


    unsigned char digest[SHA256_DIGEST_LENGTH] = { 0 };
    OpenSSL_add_all_digests(); // Initialize all available digest algorithms
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit(mdctx, EVP_sha256()); // Use SHA-256
    EVP_DigestUpdate(mdctx, hash_input_k1_i, sizeof(hash_input_k1_i)); // Update the digest with your data

    // Obtain the SHA-256 hash
    EVP_DigestFinal(mdctx, digest, NULL);
    EVP_MD_CTX_free(mdctx); // Clean up the context


    for (int i = 0; i < 8; i++) {
        s_i[i] = digest[i];
    }  // 상위8바이트만 s_i에저장


    printf("s_i: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", s_i[i]);
    }
    printf("\n"); //s_i 확인출력


    for (int i = 0; i < 17; i++) {
        printf("%02x", hash_input_k1_i[i]);
    }
    printf("\n"); //hash_input_k1_i확인 출력



    //$$$$$$$$$   3. kk_i만들기 $$$$$$$$$$$$$$

    for (int i = 0; i < 24; i++) {
        if (i >= 16) {
            hash_input_k2_Li[i] = x_i[i - 16];
        }
        else {
            hash_input_k2_Li[i] = k2[i];
        }
    }   //hash_input_k2_Li변수 저장
    //printf("hash_input_k2_Li:");
    //for (int i = 0; i < 24; i++) {
    //    printf("%02x", hash_input_k2_Li[i]);

    //}
    //printf("\n"); //hash_input_k2_Li 확인출력

    unsigned char digest2[SHA256_DIGEST_LENGTH] = { 0 };
    OpenSSL_add_all_digests(); // Initialize all available digest algorithms
    EVP_MD_CTX* mdctx2 = EVP_MD_CTX_new();
    EVP_DigestInit(mdctx2, EVP_sha256()); // Use SHA-256
    EVP_DigestUpdate(mdctx2, hash_input_k2_Li, sizeof(hash_input_k2_Li)); // Update the digest with your data

    // Obtain the SHA-256 hash
    EVP_DigestFinal(mdctx2, digest2, NULL);
    EVP_MD_CTX_free(mdctx2); // Clean up the context

    for (int i = 0; i < 32; i++) {
        kk_i[i] = digest2[i];
    }  // kk_i에저장


    //printf("kk_i: ");
    //for (int i = 0; i < 32; i++) {
    //    printf("%02x", kk_i[i]);
    //}
    //printf("\n"); //kk_i 확인출력


    // $$$$$$$$$$$$$ 4. T_i <- s_i || F_i $$$$$$$$$$$$$

    for (int i = 0; i < 40; i++) {
        if (i >= 32) {
            hash_input_kk_i_s_i[i] = s_i[i - 32];
        }
        else {
            hash_input_kk_i_s_i[i] = kk_i[i];
        }
    }   //hash_input_kk_i_s_i변수 저장

    printf("hash_input_kk_i_s_i:");
    for (int i = 0; i < 40; i++) {
        printf("%02x", hash_input_kk_i_s_i[i]);

    }
    printf("\n"); //hash_input_kk_i_s_i 확인출력


    uc F_i[SHA256_DIGEST_LENGTH] = { 0 };
    OpenSSL_add_all_digests(); // Initialize all available digest algorithms
    EVP_MD_CTX* mdctx3 = EVP_MD_CTX_new();
    EVP_DigestInit(mdctx3, EVP_sha256()); // Use SHA-256
    EVP_DigestUpdate(mdctx3, hash_input_kk_i_s_i, sizeof(hash_input_kk_i_s_i)); // Update the digest with your data

    // Obtain the SHA-256 hash
    EVP_DigestFinal(mdctx3, F_i, NULL);
    EVP_MD_CTX_free(mdctx3); // Clean up the context


    // T_i만들기
    for (int i = 0; i < 16; i++) {
        if (i >= 8) {
            T_i[i] = F_i[i - 8];
        }
        else {
            T_i[i] = s_i[i];
        }
    }

    // $$$$$$$$$$$$$ 5. XOR 연산  후  16 Bytes 길이의  변수  ci 에 저장
    for (int i = 0; i < 16; i++) {
        c_i[i] = x_i[i] ^ T_i[i];
    } //XOR연산
    printf("\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x", c_i[i]);
    }
    printf("\n");

    return c_i;
}
uc* Decrypt_word(std::vector<uint8_t> tmp) {
    uc c_i[16] = { 0 };
    for (int i = 0; i < 16; i++) {
        if (i <= tmp.size())
            c_i[i] = tmp[i];
        else
            c_i[i] = 0;
    }
    uc B[8] = { 0 };
    uc s_i[8] = { 0 };
    uc restore_hash_input_k1_i[17] = { 0 };
    uc L_i[8] = { 0 };
    uc restore_hash_input_k2_Li[24] = { 0 };
    uc kappa_i[32] = { 0 };
    uc hash_input_kappa_i_s_i[40] = { 0 };
    uc T_i[16] = { 0 };
    uc x_i_to_decrpt[16] = { 0 };


    string filename = "k0k1k2.txt";
    ifstream _kf;
    _kf.open(filename);
    
    
    char k1_char[33] = { 0 };
    char k2_char[33] = { 0 };
    char k0_char[33] = { 0 };
    if (_kf.is_open()) {
        _kf.read(k0_char, 32);
        _kf.seekg(34, std::ios::beg);
        _kf.read(k1_char, 32);
        _kf.seekg(68, std::ios::beg);
        _kf.read(k2_char, 32);
    }
    _kf.close();
    uc k0[16] = { 0 };
    uc k1[16] = { 0 };
    uc k2[16] = { 0 };

    for (int i = 0; i < 16; i++) {
        sscanf(k0_char + (i * 2), "%2hhx", &k0[i]);
        sscanf(k1_char + (i * 2), "%2hhx", &k1[i]);
        sscanf(k2_char + (i * 2), "%2hhx", &k2[i]);
    } //k1, k2을 불러와서 uc type에 저장

    for (int k = 0; k < 8; k++) {
        B[k] = c_i[k];
    }  //B만듬
    printf("c_i:");
    for (int i = 0; i < 16; i++) {
        printf("%02x", c_i[i]);
    }
    //printf("\n");
    //printf("B:");
    /*for (int i = 0; i < 8; i++) {
        printf("%02x", B[i]);
    }*/
    //printf("\n");
    //s_i만들기 시작

    for (int k = 0; k < 17; k++) {
        if (k == 16) {
            restore_hash_input_k1_i[16] = counter2;
            break;
        }
        restore_hash_input_k1_i[k] = k1[k];
    }   //hash_input_k1_i변수 저장


    unsigned char digest[SHA256_DIGEST_LENGTH] = { 0 };
    OpenSSL_add_all_digests(); // Initialize all available digest algorithms
    EVP_MD_CTX* mdctx5 = EVP_MD_CTX_new();
    EVP_DigestInit(mdctx5, EVP_sha256()); // Use SHA-256
    EVP_DigestUpdate(mdctx5, restore_hash_input_k1_i, sizeof(restore_hash_input_k1_i));
    EVP_DigestFinal(mdctx5, digest, NULL);
    EVP_MD_CTX_free(mdctx5); // Clean up the context

    for (int i = 0; i < 8; i++) {
        s_i[i] = digest[i];
    }  // 상위8바이트만 s_i에저장

    //printf("s_i: ");
    //for (int i = 0; i < 8; i++) {
    //    printf("%02x", s_i[i]);
    //}
    //printf("\n"); //s_i 확인출력

    // L_i 만들기
    for (int k = 0; k < 8; k++)
        L_i[k] = s_i[k] ^ B[k];
    //printf("L_i: ");
    //for (int i = 0; i < 8; i++) {
    //    printf("%02x", L_i[i]);
    //}
    //printf("\n"); //L_i 확인출력


    //$$$$$$$$$   3. kk_i만들기 $$$$$$$$$$$$$$
    for (int i = 0; i < 24; i++) {
        if (i >= 16) {
            restore_hash_input_k2_Li[i] = L_i[i - 16];
        }
        else {
            restore_hash_input_k2_Li[i] = k2[i];
        }
    }   //restore_hash_input_k2_Li변수 저장
    //printf("restore_hash_input_k2_Li:");
    //for (int i = 0; i < 24; i++) {
    //    printf("%02x", restore_hash_input_k2_Li[i]);
    //}
    //printf("\n"); //restore_hash_input_k2_Li 확인출력

    unsigned char digest2[SHA256_DIGEST_LENGTH] = { 0 };
    OpenSSL_add_all_digests(); // Initialize all available digest algorithms
    EVP_MD_CTX* mdctx6 = EVP_MD_CTX_new();
    EVP_DigestInit(mdctx6, EVP_sha256()); // Use SHA-256
    EVP_DigestUpdate(mdctx6, restore_hash_input_k2_Li, sizeof(restore_hash_input_k2_Li));
    EVP_DigestFinal(mdctx6, digest2, NULL);
    EVP_MD_CTX_free(mdctx6); // Clean up the context

    for (int i = 0; i < 32; i++) {
        kappa_i[i] = digest2[i];
    }  //kappa_i에저장
    //printf("kappa_i: ");
    //for (int i = 0; i < 32; i++) {
    //    printf("%02x", kappa_i[i]);
    //}
    //printf("\n"); //kk_i 확인출력

    // $$$$$$$$$$$$$ 4. T_i <- s_i || F_i $$$$$$$$$$$$$

    for (int i = 0; i < 40; i++) {
        if (i >= 32) {
            hash_input_kappa_i_s_i[i] = s_i[i - 32];
        }
        else {
            hash_input_kappa_i_s_i[i] = kappa_i[i];
        }
    }   //hash_input_kappa_i_s_i변수 저장



    uc F_i[SHA256_DIGEST_LENGTH] = { 0 };
    OpenSSL_add_all_digests(); // Initialize all available digest algorithms
    EVP_MD_CTX* mdctx7 = EVP_MD_CTX_new();
    EVP_DigestInit(mdctx7, EVP_sha256()); // Use SHA-256
    EVP_DigestUpdate(mdctx7, hash_input_kappa_i_s_i, sizeof(hash_input_kappa_i_s_i)); // Update the digest with your data

    // Obtain the SHA-256 hash
    EVP_DigestFinal(mdctx7, F_i, NULL);
    EVP_MD_CTX_free(mdctx7); // Clean up the context

    //printf("F_i: ");
    //for (int i = 0; i < 32; i++) {
    //    printf("%02x", F_i[i]);
    //}
    //printf("\n"); //F_i 확인출력

    // T_i만들기
    for (int i = 0; i < 16; i++) {
        if (i >= 8) {
            T_i[i] = F_i[i - 8];
        }
        else {
            T_i[i] = s_i[i];
        }
    }

    printf("T_i: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", T_i[i]);
    }
    printf("\n"); //T_i 확인출력

    //x_i_to_decrpt 만들기
    for (int i = 0; i < 16; i++) {
        x_i_to_decrpt[i] = c_i[i] ^ T_i[i];
    }
    printf("x_i_to_decrpt: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", x_i_to_decrpt[i]);
    }
    printf("\n"); //x_i_to_decrpt 확인출력

    uc* w_i = new uc[16];
    int outLen = 16, inBuf = 16;
    EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(aes_ctx);
    EVP_CIPHER_CTX_set_padding(aes_ctx, false);

    EVP_DecryptInit_ex(aes_ctx, EVP_aes_128_ecb(), NULL, k0, NULL);

    // Decrypt the data
    EVP_DecryptUpdate(aes_ctx, w_i, &outLen, x_i_to_decrpt, inBuf);
    printf("w_i(in decrpt func): ");
    for (int i = 0; i < 16; i++) {
        printf("%c", w_i[i]);
    }
    printf("\n");  //x_i 출력
    //printf("\n");
    // Clean up the decryption context
    EVP_CIPHER_CTX_cleanup(aes_ctx);
    // x now contains the decrypted data
    EVP_CIPHER_CTX_free(aes_ctx);
    return w_i; //초기화 해줘야함
}
void Store(string doc_file_name, tcp::socket& socket) { //파일은 동시업로드 안되고, 순차적으로 하나씩 업로드하는 시스템
    //파일에서 평문 불러오기
    string word;
    uc* encrypted_word = NULL; //c_i 받는 포인터
    ifstream doc_file(doc_file_name); //파일을 연다

    if (doc_file.is_open()) {
        Packet packet; //패킷최대페이로드는 1024
        packet.header.resize(10,0); //헤더크기만큼 초기화
        packet.header[5] = 2; //암호화된 파일 보낼테니 저장하라는뜻(command)

        //맨 처음 filename 암호화해서 전송(단 확장자 포함해서 16바이트)
        encrypted_word = Encrypt_word(doc_file_name); //단, 파일이름이 확장자 포함해서 16바이트이하여야함(띄어쓰기는 상관없음)
        printf("filename:: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", encrypted_word[i]);
            packet.payload.push_back(encrypted_word[i]);

        }
        printf("\n"); // 확인출력 및 파일이름 패킷에 넣기
        delete[]encrypted_word; encrypted_word = NULL;
        packet.header[4] = 1; //새로운 파일 업로드니까 디비에 정보 저장하라는 의미(is_new_file)

        while (getline(doc_file, word, ' ')) {
            counter++;
            encrypted_word = Encrypt_word(word);
            for (int i = 0; i < 16; i++) {
                packet.payload.push_back(encrypted_word[i]);
            }
            delete[]encrypted_word; encrypted_word = NULL;
            if (packet.payload.size() == 1024) {
                packet.header[0] = 4; //1024는 16진수로 400
                std::ostringstream oss;
                boost::archive::binary_oarchive oa(oss);
                oa << packet;
                asio::write(socket, asio::buffer(oss.str()));

                ///////
                //std::istringstream is(oss.str());
                //boost::archive::binary_iarchive ia(is);
                //std::cout << "리시브드패킷: ";

                //Packet receivedPacket;

                //ia >> receivedPacket;
                //std::cout << "receivedPacke: "  << std::endl;
                //for (int i = 0; i < receivedPacket.payload.size(); i++) {
                //    printf("%02x", receivedPacket.payload[i]);
                //}
                // Send the serialized packet to the server

                // Output debug information
                std::cout << "Header size: " << packet.header.size() << std::endl;
                std::cout << "Payload size: " << packet.payload.size() << std::endl;
                packet.header[4] = 0; //이제 파일이름 포함한 패킷은 보냇다는뜻 (is_new_file==0)
                Sleep(500);
                cout << "oss.str().size()" << oss.str().size()<< endl;;
                packet.payload.clear();
            }
        }
        if (packet.payload.size() > 0) {
            int payload_size = packet.payload.size();
            cout << "payload_size " << packet.payload.size() << endl;
            for (int i = 16; i < payload_size; i++)
                printf("%02x", packet.payload.at(i));
            std::stringstream DtoH;
            DtoH << std::hex << payload_size;
            string H = DtoH.str();
            std::vector<unsigned char> ucArray;

            for (char c : H) {
                // Convert the hexadecimal character to unsigned char
                unsigned char uc = static_cast<unsigned char>(std::stoi(std::string(1, c), nullptr, 16));
                ucArray.push_back(uc);
            }

            packet.header[0] = 0; packet.header[1] = 0; packet.header[2] = 0;
            if (H.size() == 1) packet.header[2] = ucArray[0];
            else if (H.size() == 2) {
                packet.header[1] = ucArray[0];
                packet.header[2] = ucArray[1];
            }
            else { //H.size() == 3
                for (int i = 0; i < H.size(); i++) {
                    cout << "H[i]" << H[i] << endl;
                    packet.header[i] = ucArray[i];
                    cout << "packet.header[i] " << (int)packet.header[i] << endl;
                }
            }
            ucArray.clear();
            std::ostringstream oss;
            boost::archive::binary_oarchive oa(oss);
            oa << packet;

            // Send the serialized packet to the server
            asio::write(socket, asio::buffer(oss.str()));
            // Output debug information
            std::cout << "Header size: " << packet.header.size() << std::endl;
            std::cout << "Payload size: " << packet.payload.size() << std::endl;
            Sleep(500);

            cout << "packet.payload.size() " << packet.payload.size() << endl;
            packet.payload.clear(); 

        }
        encrypted_word = NULL;
        counter = 1;
    }
    else {
        cerr << "존재하지 않는 파일입니다.." << endl;
    }
    //파일전송끝났음을알리기
    doc_file.close();
    Packet packet_; //패킷최대페이로드는 1024
    packet_.header.resize(10, 0); // 헤더크기만큼 일단 늘림
    packet_.header[5] = 7; // 모든 파일전송햇으니 소켓닫아도된다
    packet_.header[2] = 1; // 페이로드크기:1 그냥 임의설정
    packet_.payload.push_back(1);
    // Serialize the Packet
    std::ostringstream oss;
    boost::archive::binary_oarchive oa(oss);
    oa << packet_;
    asio::write(socket, asio::buffer(oss.str()));
    //socket.close();
}
unordered_set<string> Build_W(string keyword_filename) {
    // Bulid W 
    ifstream fin;
    fin.open(keyword_filename);

    string line;
    std::unordered_set<std::string> keywords_set; // W


    while (!fin.eof())
    {
        getline(fin, line);
        //cout << line << endl;
        istringstream ss(line);
        string keyword;
        int index = 0;

        while (getline(ss, keyword, ' ')) {
            if (index == 0) {
                index++;
                continue;
            }
            if (keyword.back() == ',')
                keyword = keyword.substr(0, keyword.length() - 1);
            index++;
            keywords_set.insert(keyword);
            //std::cout << keyword << std::endl;
        }
    }
    ////확인출력
    //cout << "W 확인출력: " ;
    //for (const string& a_keyword : keywords_set) {
    //    cout << a_keyword << " ";
    //}
    //cout << endl;
    fin.close();
    return keywords_set;
}
unordered_map<string, unordered_set<string>> Build_IID(unordered_set<string> keywords_set) {
    unordered_map<string, unordered_set<string>> IID;

    for (const string& a_keyword : keywords_set) {

        string line;
        std::unordered_set<string> file_id_list; // 한 개 키워드 대응되는 파일아이디들(아직 string)
        //uc* IID = new uc[sizeof(file_id)];
        //cout << a_keyword << ": ";
        ifstream fin;
        fin.open("id_keywords.txt");
        while (!fin.eof())
        {
            getline(fin, line);
            //cout << line << endl;
            std::unordered_set<std::string> a_line_keywords_set; // 한 줄의 키워드들만 모아놓은 set
            istringstream ss(line);
            string keyword;
            string file_id_str;
            int index = 0;
            while (getline(ss, keyword, ' ')) {
                if (index == 0) {
                    file_id_str = keyword.substr(0, keyword.length() - 1);
                    index++;
                    continue;
                }
                if (keyword.back() == ',')
                    keyword = keyword.substr(0, keyword.length() - 1);
                a_line_keywords_set.insert(keyword); //한 파일에 해당하는 키워드들의 세트 완성
                //std::cout << keyword << std::endl;
            }
            if (a_line_keywords_set.count(a_keyword)) {
                file_id_list.insert(file_id_str);
                //cout << file_id_str;
            }
        }

        IID[a_keyword] = file_id_list;
        fin.close();
    }
    //확인출력
    /*for (const auto& pair : IID) {
        std::cout << pair.first << ": ";
        for (const auto& value : pair.second) {
            std::cout << value << " ";
        }
        std::cout << std::endl;
    }
    */
    return IID;
}
unordered_map<string, vector<uc>> Build_T(unordered_map<string, unordered_set<string>> IID) {
    // Ks 불러오기
    string key_filename = "kdkskt.txt";
    ifstream kf;
    kf.open(key_filename);
    char ks_char[33] = { 0 };

    if (kf.is_open()) {
        kf.seekg(34, std::ios::beg);
        kf.read(ks_char, 32);
    }
    else {
        cout << "키 불러오기 에러" << endl;
    }
    uc Ks[16] = { 0 };
    cout << "ks_char" << ks_char << endl;
    for (int i = 0; i < 16; i++) {
        sscanf(ks_char + (i * 2), "%2hhx", &Ks[i]);
    }
    printf("Ks: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", Ks[i]);
    }
    kf.close();
    unordered_map<string, vector<uc>> T;

    for (const auto& keyword : IID) { //딕셔너리 요소 하나를 가져옴(ex. "string": 1)
        // Ke 만들기
        uc Ke[16] = { 0 };
        uc kw_to_str[16] = { 0 };
        for (int i = 0; i < 16; i++) {
            if (i < strlen(keyword.first.c_str()))
                kw_to_str[i] = (unsigned char)keyword.first.c_str()[i];
            else
                kw_to_str[i] = 0;
        }
        int outLen = 16, inBuf = 16;
        EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(aes_ctx);
        EVP_CIPHER_CTX_set_padding(aes_ctx, false);
        EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_ecb(), 0, Ks, 0);
        EVP_EncryptUpdate(aes_ctx, Ke, &outLen, kw_to_str, inBuf);
        EVP_CIPHER_CTX_cleanup(aes_ctx);
        printf("Ke: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", Ke[i]);
        }
        printf("\n");  //Ke 출력
        EVP_CIPHER_CTX_free(aes_ctx);

        std::cout << keyword.first << ": "; // keyword.first: string에 해당
        vector<uc> e_file_ids; // w에 해당되는 암호화된 파일아이디들을 저장 (==t)

        for (const auto& value : keyword.second) { // keyword.second: 1에 해당 여기선 벡터므로 value는 벡터 요소들을 가리킴
            uc buff[16] = { 0 }; // 파일인덱스 저장할 것-총 파일 개수는 두자리수 아래이긴 한데 16배수여야 하므로
            uc eid[16] = { 0 };
            for (int i = 0; i < 16; i++) { //파일인덱스는 숫자로 취급함 한 파일인덱스255 넘으면 uc하나에 저장못하므로 안됨
                if (i == 0)
                    buff[i] = (uc)stoi(value);
                else
                    buff[i] = 0;
            }
            cout << "buff[0]: " << (int)buff[0] << endl;
            int outLen = 16, inBuf = 16;
            EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
            EVP_CIPHER_CTX_init(aes_ctx);
            EVP_CIPHER_CTX_set_padding(aes_ctx, false);
            EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_ecb(), 0, Ke, 0);
            EVP_EncryptUpdate(aes_ctx, eid, &outLen, buff, inBuf);
            EVP_CIPHER_CTX_cleanup(aes_ctx);
            printf("eid: ");
            for (int i = 0; i < 16; i++) {
                printf("%02x", eid[i]);
                e_file_ids.push_back(eid[i]);

            }
            printf("\n");  //eid 출력
            EVP_CIPHER_CTX_free(aes_ctx);

        }
        T[keyword.first] = e_file_ids;
        e_file_ids.clear();
    }
    //확인출력
    for (const auto& pair : T) {
        std::cout << "Key: " << pair.first << ", Value: [";

        // vector<unsigned char> 출력
        for (const auto& value : pair.second) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(value);
        }

        std::cout << "]" << std::endl;
    }

    return T;
}
void TSetSetup(tcp::socket& socket, unordered_map<string, vector<uc>> T,
    unordered_set<string> keywords_set, unsigned int const B, unsigned int const S) {
    // Kt 불러오기
    string _key_filename = "kdkskt.txt";
    ifstream _kf;
    _kf.open(_key_filename);
    char kt_char[33] = { 0 };

    if (_kf.is_open()) {
        _kf.seekg(68, std::ios::beg);
        _kf.read(kt_char, 32);
    }
    else {
        cout << "키 불러오기 에러" << endl;
    }
    uc Kt[16] = { 0 };
    for (int i = 0; i < 16; i++) {
        sscanf(kt_char + (i * 2), "%2hhx", &Kt[i]);
    }
    printf("Kt: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", Kt[i]);
    }
    _kf.close();

    // Tset 선언
    std::bitset<80> label;
    std::bitset<129> value; //자동으로 모두 0으로 초기화

    // B x S 크기의 2차원 배열 동적 할당
    MyPair** Tset; //티셋 포인터
    Tset = new MyPair*[B];
    for (int i = 0; i < B; i++) {
        Tset[i] = new MyPair[S];
    }
    //for (int i = 0; i < B; ++i) {
    //    for (int j = 0; j < S; ++j) {
    //        Tset[i][j]= make_pair(label, value); // 동적 2차원 배열에 값 설정
    //    }
    //}

    // Free 선언
    // 2차원 벡터 만들기
    std::vector<std::vector<uc>> Free;
    std::vector<uc> s;
    for (uc i = 0; i < B; i++) {
        s.push_back(i);
    }
    for (uc i = 0; i < S; i++) {
        Free.push_back(s);
    }


    // 2차원 벡터 출력
    /*for (const auto& row : Free) {
        for (uc element : row) {
            std::cout << (int)element << " ";
        }
        std::cout << std::endl;
    }*/



retry_outer:

    for (const string& a_keyword : keywords_set) {
        // stag 만들기
        cout << a_keyword << " ";
        uc kw_to_str[16] = { 0 };
        for (int i = 0; i < 16; i++) {
            if (i < strlen(a_keyword.c_str()))
                kw_to_str[i] = (unsigned char)a_keyword.c_str()[i];
            else
                kw_to_str[i] = 0;
        }
        uc stag[16] = { 0 };
        int outLen = 16, inBuf = 16;
        EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(aes_ctx);
        EVP_CIPHER_CTX_set_padding(aes_ctx, false);
        EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_ecb(), 0, Kt, 0);
        EVP_EncryptUpdate(aes_ctx, stag, &outLen, kw_to_str, inBuf);
        EVP_CIPHER_CTX_cleanup(aes_ctx);
        printf("stag: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", stag[i]);
        }
        printf("\n");  //stag 출력
        EVP_CIPHER_CTX_free(aes_ctx);

        // T[w]=(암호화된파일아이디들)   w == a_keyword
        vector<uc>* fileID_ptr = &T[a_keyword]; //벡터포인터로 암호화된파일아이디들의 첫번쨰요소를가리킴
        int fileID_len = T[a_keyword].size() / 16;
        cout << a_keyword << "의 " << "암호회된 fileID_len: " << fileID_len << endl;

        try {
            for (int i = 1; i <= fileID_len; i++) { // for (i= 1 to tw) do:
                // AES(stag, i) i는 그냥 자연수의 iter
                uc iter_i[16] = { 0 };
                uc hash_input[16] = { 0 };
                for (int k = 0; k < 16; k++) {
                    if (k == 0)
                        iter_i[k] = (unsigned char)i; //한 키워드에 255개의 id들있을수있음 그이상은안됨(ppt상ok)
                    else
                        iter_i[k] = 0;
                }
                int outLen = 16, inBuf = 16;
                EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
                EVP_CIPHER_CTX_init(aes_ctx);
                EVP_CIPHER_CTX_set_padding(aes_ctx, false);
                EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_ecb(), 0, stag, 0);
                EVP_EncryptUpdate(aes_ctx, hash_input, &outLen, iter_i, inBuf);
                EVP_CIPHER_CTX_cleanup(aes_ctx);
                printf("hash_input: ");
                for (int i = 0; i < 16; i++) {
                    printf("%02x", hash_input[i]);
                }
                printf("\n");  //hash_input 출력
                EVP_CIPHER_CTX_free(aes_ctx);

                // 암호화된 값을 hash 함수로 매핑
                unsigned char digest[SHA256_DIGEST_LENGTH] = { 0 };
                OpenSSL_add_all_digests(); // Initialize all available digest algorithms
                EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
                EVP_DigestInit(mdctx, EVP_sha256()); // Use SHA-256
                EVP_DigestUpdate(mdctx, hash_input, sizeof(hash_input)); // Update the digest with your data
                EVP_DigestFinal(mdctx, digest, NULL);
                EVP_MD_CTX_free(mdctx); // Clean up the context
                printf("digest: ");
                for (int i = 0; i < 32; i++) {
                    printf("%02x", digest[i]);
                }
                printf("\n");  //digest 출력(b||L||K 로 나눌값)
                // b||L||K 로 나누기 (7bits, 80, 129)
                std::bitset<7> b(digest[0] >> 1);

                std::bitset<88> temp_L;
                for (int i = 0; i < 11; ++i) {
                    temp_L <<= 8; // temp_L의  모든 비트를 왼쪽으로 8만큼 이동
                    temp_L |= std::bitset<88>(digest[i]); // or 연산 후 할당 즉, 붙여넣기
                }
                std::bitset<80> L(temp_L.to_string().substr(7, 80));

                std::bitset<216> temp_K;
                for (int i = 0; i < 27; ++i) {
                    temp_K <<= 8; // temp_K의  모든 비트를 왼쪽으로 8만큼 이동
                    temp_K |= std::bitset<216>(digest[i]); // or 연산 후 할당 즉, 붙여넣기
                }
                std::bitset<129> K(temp_K.to_string().substr(87, 129));
                // 확인 출력
                cout << "b:" << b << endl;
                cout << "L:" << L << endl;
                cout << "K:" << K << endl;

                int b_decimal = 0;
                for (int i = 0; i < 7; i++) {
                    b_decimal += b[i] * pow(2, i);
                }
                cout << "b_decimal: " << std::dec << b_decimal << endl;

                // abort 추가해야함
                if (Free[b_decimal].size() == 0) {
                    cout << "Free 자리없음 다시 연산 . . ." << endl;
                    throw std::exception();
                }

                // 난수 생성기 생성
                std::random_device rd;
                std::mt19937 generator(rd());
                std::size_t vectorSize = Free[b_decimal].size(); // 벡터의 크기 얻기
                std::uniform_int_distribution<std::size_t> distribution(0, vectorSize - 1); // 균등 분포 생성
                std::size_t j = distribution(generator); // 랜덤한 인덱스 생성

                // 랜덤하게 선택된 요소 출력
                std::cout << "Randomly selected element: " << Free[b_decimal][j] << std::endl;
                Free[b_decimal].erase(Free[b_decimal].begin() + j);

                int betta = 0;
                if (i < fileID_len)
                    betta = 1;
                else // i == tw
                    betta = 0;


                // ei 만들기 == temp
                vector<uc> temp;
                temp.insert(temp.begin(), T[a_keyword].begin() + (i - 1) * 16, T[a_keyword].begin() + (i - 1) * 16 + 16);

                // betta_ei 만들기
                std::bitset<129> betta_ei;
                for (int i = 0; i < 16; ++i) {
                    betta_ei <<= 8; // 모든 비트를 왼쪽으로 8만큼 이동
                    betta_ei |= std::bitset<129>(temp[i]); // or 연산 후 할당 즉, 붙여넣기
                }
                betta_ei[128] = betta;
                cout << "betta_ei: " << betta_ei << endl;

                // Tset에 label, value 값 저장
                Tset[b_decimal][j]=make_pair(L, betta_ei ^ K);
                cout << "Tset[b_decimal][j].first" << Tset[b_decimal][j].first.to_string() << endl;
                cout << "Tset[b_decimal][j].second" << Tset[b_decimal][j].second.to_string() << endl;//결과정상적

            }
        }
        catch (const std::exception& e) {
            goto retry_outer; //다시 루프 첫번째로 돌아감
        }
    }

    //Tset 확인출력
    /*for (int i = 15; i < 64; ++i) {
        for (int j = 15; j < 64; ++j) {
            std::cout << "Tset[" << i << "][" << j << "].first: " << Tset[i][j].first.to_string();
        }
    }*/
    //   Tset 파일에 저장 및 서버한테 전송하기
    cout << "sizeof(MyPair):" << sizeof(MyPair) << endl;
    // 파일에 저장
    std::ofstream ofs("Tset.bin", std::ios::binary);
    for (int i = 0; i < 128; ++i) {
        for (int j = 0; j < 128; ++j) {
            ofs.write(reinterpret_cast<char*>(&Tset[i][j]), sizeof(MyPair));
        }
    }
    ofs.close();
    //Tset 확인출력
    /*for (int i = 15; i < 65; ++i) {
        for (int j = 15; j < 64; ++j) {
            std::cout << "Tset[" << i << "][" << j << "].first: " << Tset[i][j].first.to_string() << std::endl;
            std::cout << "Tset[" << i << "][" << j << "].second: " << Tset[i][j].second.to_string() << std::endl;
        }
    }*/

    ////      서버에게 패킷타이징해서 보내기 - 티셋가로세로크기인풋에넣기 지금은하드코딩되어있음

    Packet packet; //패킷최대페이로드는 1024
    packet.header.resize(10, 0); // 헤더크기만큼 일단 늘림
    packet.header[5] = 1; //Tset 전송할테니 받으라는 뜻
    packet.header[4] = 1; //새로운 Tset 업로드니까 디비에 정보 저장하라는 의미(is_new_file)



    // Serialize Tset and store the serialized data in the payload
    const std::size_t arraySize = 128 * 128 * sizeof(MyPair);
    unsigned char buffer[arraySize];  // This should contain your serialized data

    // Serialization
    std::size_t offset = 0;
    for (int i = 0; i < 128; ++i) {
        for (int j = 0; j < 128; ++j) {
            std::memcpy(&buffer[offset], &Tset[i][j], sizeof(MyPair));
            offset += sizeof(MyPair);
        }
    }


    size_t Tset_size = sizeof(buffer);
    cout << "Tset_size " << Tset_size << endl;
    size_t index = 0;
    while (Tset_size > 0) {
        size_t payload_size = 0;
        for (int i = 0; i < Tset_size; i++) {
            if (payload_size == 1024) break;
            packet.payload.push_back(buffer[i + index]);
            payload_size++;
        }
        index += payload_size;
        Tset_size -= payload_size;

        std::stringstream DtoH;
        DtoH << std::hex << payload_size;
        string H = DtoH.str();
        std::vector<unsigned char> ucArray;

        for (char c : H) {
            // Convert the hexadecimal character to unsigned char
            unsigned char uc = static_cast<unsigned char>(std::stoi(std::string(1, c), nullptr, 16));
            ucArray.push_back(uc);
        }

        packet.header[0] = 0; packet.header[1] = 0; packet.header[2] = 0; //패킷 재활용하기때문임
        if (H.size() == 1) packet.header[2] = ucArray[0];
        else if (H.size() == 2) {
            packet.header[1] = ucArray[0];
            packet.header[2] = ucArray[1];
        }
        else { //H.size() == 3
            for (int i = 0; i < H.size(); i++) {
                cout << "H[i]" << H[i] << endl;
                packet.header[i] = ucArray[i];
                cout << "packet.header[i] " << (int)packet.header[i] << endl;
            }
        }
        ucArray.clear();


        // Serialize the Packet
        std::ostringstream oss;
        boost::archive::binary_oarchive oa(oss);
        oa << packet;

        // Send the serialized packet to the server
        asio::write(socket, asio::buffer(oss.str()));
        // Output debug information
        std::cout << "Header size: " << packet.header.size() << std::endl;
        std::cout << "Payload size: " << packet.payload.size() << std::endl;


        packet.header[4] = 0; //이제 남은 데이터 보내면 됨(is_new_file==0)
        Sleep(10);
        packet.payload.clear();

    }
    //티셋전송끝났음을알리기
    Packet packet_; //패킷최대페이로드는 1024
    packet_.header.resize(10, 0); // 헤더크기만큼 일단 늘림
    packet_.header[5] = 7; // 모든 파일전송햇으니 소켓닫아도된다
    packet_.header[2] = 1; // 페이로드크기:1 그냥 임의설정
    packet_.payload.push_back(1);
    // Serialize the Packet
    std::ostringstream oss;
    boost::archive::binary_oarchive oa(oss);
    oa << packet_;
    asio::write(socket, asio::buffer(oss.str()));
    //  티셋 메모리 해지
    for (int i = 0; i < B; ++i) {
        delete[] Tset[i];
    }
    delete[] Tset;
    //socket.close();

}
uc* TSetGetTag(uc Kt[16], string w) {
    uc buff[16] = { 0 };
    uc* stag= new uc[16];
    for (int i = 0; i < 16; i++) {
        if (i < strlen(w.c_str()))
            buff[i] = (unsigned char)w.c_str()[i];
        else
            buff[i] = 0;
    }
    int outLen = 16, inBuf = 16;
    EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(aes_ctx);
    EVP_CIPHER_CTX_set_padding(aes_ctx, false);
    EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_ecb(), 0, Kt, 0);
    EVP_EncryptUpdate(aes_ctx, stag, &outLen, buff, inBuf);
    EVP_CIPHER_CTX_cleanup(aes_ctx);
    printf("stag in TSetGetTag: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", stag[i]);
    }
    printf("\n");  //확인출력
    EVP_CIPHER_CTX_free(aes_ctx);

    return stag;
}
void Query_keyword (string query_word,uc* Kt, tcp::socket& socket) {
    cout << "in Query_keyword func" << endl;
    uc* stag=TSetGetTag(Kt, query_word); //나중에 메모리 해지해야함

    Packet packet; //패킷최대페이로드는 1024
    packet.header.resize(10, 0); // 헤더크기만큼 일단 늘림
    packet.header[5] = 3; // 키워드 쿼리할거란 명령(stag보낸다는뜻)
    packet.header[4] = 1; //(is_new_file)
    for (int i = 0; i < 16; i++)
        packet.payload.push_back(stag[i]);

    delete[]stag; stag = NULL;// 메모리 해지 

    size_t payload_size = 16;
    std::stringstream DtoH;
    DtoH << std::hex << payload_size;
    string H = DtoH.str();
    std::vector<unsigned char> ucArray;

    for (char c : H) {
        // Convert the hexadecimal character to unsigned char
        unsigned char uc = static_cast<unsigned char>(std::stoi(std::string(1, c), nullptr, 16));
        ucArray.push_back(uc);
    }

    packet.header[0] = 0; packet.header[1] = 0; packet.header[2] = 0; //패킷 재활용하기때문임
    if (H.size() == 1) packet.header[2] = ucArray[0];
    else if (H.size() == 2) {
        packet.header[1] = ucArray[0];
        packet.header[2] = ucArray[1];
    }
    else { //H.size() == 3
        for (int i = 0; i < H.size(); i++) {
            cout << "H[i]" << H[i] << endl;
            packet.header[i] = ucArray[i];
            cout << "packet.header[i] " << (int)packet.header[i] << endl;
        }
    }
    ucArray.clear();


    // Serialize the Packet
    std::ostringstream oss;
    boost::archive::binary_oarchive oa(oss);
    oa << packet;

    // Send the serialized packet to the server
    asio::write(socket, asio::buffer(oss.str()));
    // Output debug information
    std::cout << "Header size: " << packet.header.size() << std::endl;
    std::cout << "Payload size: " << packet.payload.size() << std::endl;

}
void Query_documents(tcp::socket& socket,string keyword) {//암호화된 파일아이디들 받고 복호화해서 재전송
    cout << "in Query_document func" << endl;
    // 암호화된 파일아이디들 받는코드
    vector<uc> V;
    while (1) {
        cout << "in Query_document while loop" << endl;
        boost::system::error_code error;
        string serializedPacket; //최대페이로드 1024바이트,헤더10바이트
        serializedPacket.resize(2048);
        size_t response_length = socket.read_some(asio::buffer(serializedPacket), error);
        std::cout << "response_length: " << response_length << std::endl;

        // Deserialize the received data into a Packet
        std::istringstream is(serializedPacket);
        boost::archive::binary_iarchive ia(is);
        Packet receivedPacket;
        ia >> receivedPacket;
        // 헤더 검사
        if (is_new_packet == 1) {
            vector<uint8_t> header = receivedPacket.header;
            payload_len = static_cast<int>(receivedPacket.header[0]) * 16 * 16 + static_cast<int>(receivedPacket.header[1]) * 16 + static_cast<int>(receivedPacket.header[2]);
            std::cout << "new payload len:" << payload_len << endl;
            is_new_packet = 0;
        }

        size_t rcvd_packet_len = receivedPacket.header.size() + receivedPacket.payload.size();
        cout << "rcvd_packet_len" << rcvd_packet_len << endl;

        if (payload_len == (rcvd_packet_len - HEADER_SIZE)) {
            vector<uint8_t> payload = receivedPacket.payload;
            is_new_packet = 1;
        }

        // Output debug information
        std::cout << "Header size: " << receivedPacket.header.size() << std::endl;
        std::cout << "Payload size: " << receivedPacket.payload.size() << std::endl;
        if (receivedPacket.header[5] == 7) {
            break; //종료알림
        }

        V.insert(V.begin(), receivedPacket.payload.begin(), receivedPacket.payload.end());
        if (V.size() == 1) {
            cout << "키워드 존재하는 파일없음" << endl;
            no_keyword = 1;
            Packet packet; //패킷최대페이로드는 1024
            packet.header.resize(10, 0); // 헤더크기만큼 일단 늘림
            packet.header[5] = 7; 
            packet.header[2] = 1; // 페이로드크기:1 그냥 임의설정
            packet.payload.push_back(1);
            // Serialize the Packet
            std::ostringstream oss;
            boost::archive::binary_oarchive oa(oss);
            oa << packet;
            asio::write(socket, asio::buffer(oss.str()));
            //exit(1); // 프로그램 종료
            break;
        }
    }
    if (no_keyword == 0) {
        //파일 아이디 복호화
        // Ks 불러오기
        string key_filename = "kdkskt.txt";
        ifstream kf;
        kf.open(key_filename);
        char ks_char[33] = { 0 };

        if (kf.is_open()) {
            kf.seekg(34, std::ios::beg);
            kf.read(ks_char, 32);
        }
        else {
            cout << "키 불러오기 에러" << endl;
        }
        uc Ks[16] = { 0 };
        cout << "ks_char" << ks_char << endl;
        for (int i = 0; i < 16; i++) {
            sscanf(ks_char + (i * 2), "%2hhx", &Ks[i]);
        }
        printf("Ks: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", Ks[i]);
        }
        kf.close();

        // Ke 만들기
        uc Ke[16] = { 0 };
        uc kw_to_str[16] = { 0 };
        for (int i = 0; i < 16; i++) {
            if (i < strlen(keyword.c_str()))
                kw_to_str[i] = (unsigned char)keyword.c_str()[i];
            else
                kw_to_str[i] = 0;
        }
        int outLen = 16, inBuf = 16;
        EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(aes_ctx);
        EVP_CIPHER_CTX_set_padding(aes_ctx, false);
        EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_ecb(), 0, Ks, 0);
        EVP_EncryptUpdate(aes_ctx, Ke, &outLen, kw_to_str, inBuf);
        EVP_CIPHER_CTX_cleanup(aes_ctx);
        printf("Ke: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", Ke[i]);
        }
        printf("\n");  //Ke 출력
        EVP_CIPHER_CTX_free(aes_ctx);

        // id들 복호화
        vector<uc> plain_Ids;
        int iterlen = 0;
        for (int i = 0; i < V.size() / 16; i++) {
            uc eid[16] = { 0 };
            for (int i = 0; i < 16; i++) {
                eid[i] = V[iterlen + i];
            }
            iterlen += 16;
            uc plain[16] = { 0 };
            int outLen = 16, inBuf = 16;
            EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
            EVP_CIPHER_CTX_init(aes_ctx);
            EVP_CIPHER_CTX_set_padding(aes_ctx, false);

            EVP_DecryptInit_ex(aes_ctx, EVP_aes_128_ecb(), NULL, Ke, NULL);

            // Decrypt the data
            EVP_DecryptUpdate(aes_ctx, plain, &outLen, eid, inBuf);
            printf("plain file id(in decrpt func): ");
            for (int i = 0; i < 16; i++) {
                printf("%c", plain[i]);
            }
            printf("\n");  //출력
            //printf("\n");
            // Clean up the decryption context
            EVP_CIPHER_CTX_cleanup(aes_ctx);
            // x now contains the decrypted data
            EVP_CIPHER_CTX_free(aes_ctx);
            plain_Ids.push_back(plain[0]);

        }
        cout << "plain_Ids의사이즈: " << plain_Ids.size() << endl;

        //  서버에 plain_Ids들 전송코드

        Packet packet; //패킷최대페이로드는 1024
        packet.header.resize(10, 0); // 헤더크기만큼 일단 늘림
        packet.header[5] = 5; //id 전송할테니 받으라는 뜻
        packet.header[4] = 1; //새로운 id쿼리라는뜻 (is_new_file)


        size_t ID_size = plain_Ids.size();
        cout << "ID_size " << ID_size << endl;
        size_t index = 0;
        while (ID_size > 0) {
            size_t payload_size = 0;
            for (int i = 0; i < ID_size; i++) {
                if (payload_size == 1024) break;
                packet.payload.push_back(plain_Ids[i + index]);
                payload_size++;
            }
            index += payload_size;
            ID_size -= payload_size;

            std::stringstream DtoH;
            DtoH << std::hex << payload_size;
            string H = DtoH.str();
            std::vector<unsigned char> ucArray;

            for (char c : H) {
                // Convert the hexadecimal character to unsigned char
                unsigned char uc = static_cast<unsigned char>(std::stoi(std::string(1, c), nullptr, 16));
                ucArray.push_back(uc);
            }

            packet.header[0] = 0; packet.header[1] = 0; packet.header[2] = 0; //패킷 재활용하기때문임
            if (H.size() == 1) packet.header[2] = ucArray[0];
            else if (H.size() == 2) {
                packet.header[1] = ucArray[0];
                packet.header[2] = ucArray[1];
            }
            else { //H.size() == 3
                for (int i = 0; i < H.size(); i++) {
                    cout << "H[i]" << H[i] << endl;
                    packet.header[i] = ucArray[i];
                    cout << "packet.header[i] " << (int)packet.header[i] << endl;
                }
            }
            ucArray.clear();


            // Serialize the Packet
            std::ostringstream oss;
            boost::archive::binary_oarchive oa(oss);
            oa << packet;

            // Send the serialized packet to the server
            asio::write(socket, asio::buffer(oss.str()));
            // Output debug information
            std::cout << "Header size: " << packet.header.size() << std::endl;
            std::cout << "Payload size: " << packet.payload.size() << std::endl;


            packet.header[4] = 0; //이제 남은 데이터 보내면 됨(is_new_file==0)
            Sleep(10);
            packet.payload.clear();

        }
    }
}
void Restore(tcp::socket& socket) {
    cout << "in Restore func" << endl;

    ofstream FileRestored; //복호화한 단어 쓸 파일 열기

    while (1) {
        boost::system::error_code error;
        string serializedPacket; //최대페이로드 1024바이트,헤더10바이트
        serializedPacket.resize(2048);
        size_t response_length = socket.read_some(asio::buffer(serializedPacket), error);
        std::cout << "response_length: " << response_length << std::endl;

        if (error == boost::asio::error::eof) {
            std::cout << "Server closed the connection." << std::endl;
            //socket.close();
            break; // 서버가 연결 끊어버린 경우
        }
        else if (error) {
            std::cerr << "Error reading data: " << error.message() << std::endl;
            //socket.close();
            break; // Exit the loop on error
        }

        // Deserialize the received data into a Packet
        std::istringstream is(serializedPacket);
        boost::archive::binary_iarchive ia(is);
        Packet receivedPacket;
        ia >> receivedPacket;
        // 헤더 검사
        if (is_new_packet == 1) {
            vector<uint8_t> header = receivedPacket.header;
            payload_len = static_cast<int>(receivedPacket.header[0]) * 16 * 16 + static_cast<int>(receivedPacket.header[1]) * 16 + static_cast<int>(receivedPacket.header[2]);
            std::cout << "new payload len:" << payload_len << endl;
            is_new_packet = 0;
        }

        size_t rcvd_packet_len = receivedPacket.header.size()+ receivedPacket.payload.size();
        cout << "rcvd_packet_len" << rcvd_packet_len << endl;

        if (payload_len == (rcvd_packet_len - HEADER_SIZE)) {
            vector<uint8_t> payload = receivedPacket.payload;
            is_new_packet = 1;
        }

        // Output debug information
        std::cout << "Header size: " << receivedPacket.header.size() << std::endl;
        std::cout << "Payload size: " << receivedPacket.payload.size() << std::endl;
        if (receivedPacket.header.at(5) == 7) {
        // 종료 - 모든 파일 전송 완료
            break;
        }
        if (receivedPacket.header.at(4) == 1) { //어떤 새 파일을 찾았고 전송 시작될거임
            counter2 = 1;
            FileRestored.close();
            int k = 0;
            while (payload_len > 0) {
                std::vector<uint8_t> tmp;
                tmp.insert(tmp.begin(), receivedPacket.payload.begin() + k, receivedPacket.payload.begin() + k + 16);

                if (k == 0) {
                    uc* filename = Decrypt_word(tmp);
                    char a[16] = { 0 };
                    for (int i = 0; i < 16; i++) {
                        a[i] = (char)filename[i];
                    }
                    string s(a);
                    cout << "decrpted filename:" << s << endl;
                    FileRestored.open(s);
                    //파일이름받아서 파일 만들고 열기만함
                    delete[]filename; filename = NULL;
                }
                else {
                    counter2++;
                    uc* word = Decrypt_word(tmp);
                    char a[16] = { 0 };
                    for (int i = 0; i < 16; i++) {
                        a[i] = (char)word[i];
                    }
                    string s(a);
                    cout << "decryt_data:" << s;

                    FileRestored.write(a, s.size());
                    FileRestored.write(" ", 1); // 띄어쓰기
                    delete[] word; word = NULL;
                }
                tmp.clear();
                payload_len -= 16;
                k += 16;

            }

        }
        else {//packet.header.at(4) == 0 파일을 전송중임
            if (FileRestored.is_open()) {
                cout << "new payload len(in:packet.header.at(1) == 2):" << payload_len << endl;

                int k = 0;
                while (payload_len > 0) {
                    std::vector<uint8_t> tmp;
                    tmp.insert(tmp.begin(), receivedPacket.payload.begin() + k, receivedPacket.payload.begin() + k + 16);
                    counter2++;
                    uc* word = Decrypt_word(tmp);
                    char a[16] = { 0 };
                    for (int i = 0; i < 16; i++) {
                        a[i] = (char)word[i];
                    }
                    string s(a);
                    cout << "decryt_data:" << s;

                    FileRestored.write(a, s.size());
                    FileRestored.write(" ", 1); // 띄어쓰기
                    delete[] word; word = NULL;
                    tmp.clear();
                    payload_len -= 16;
                    k += 16;
                }

            }
        }
    }

    //socket.close(); //  여기서 클라이언트는 소켓 닫음
}
int main() {
    /*
    // Kd, Ks 생성
    uc Kd[16] = { 0 };
    RAND_bytes(Kd, 16);
    uc Ks[16] = { 0 };
    RAND_bytes(Ks, 16);
    uc Kt[16] = { 0 };
    RAND_bytes(Kt, 16);
    ofstream kf;
    string key_filename = "kdkskt.txt";
    kf.open(key_filename);
    if (kf.is_open()) {
        for (int i = 0; i < sizeof(Kd); i++) {
            kf << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(Kd[i]);
        }
        kf << '\n';
        for (int i = 0; i < sizeof(Ks); i++) {
            kf << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(Ks[i]);
        }
        kf << '\n';
        for (int i = 0; i < sizeof(Kt); i++) {
            kf << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(Kt[i]);
        }
    }
    else {
        cout << "키 저장 에러" << endl;
    }
    kf.close();
    */
    
    // Kt 불러오기
    string _key_filename = "kdkskt.txt";
    ifstream _kf;
    _kf.open(_key_filename);
    char kt_char[33] = { 0 };

    if (_kf.is_open()) {
        _kf.seekg(68, std::ios::beg);
        _kf.read(kt_char, 32);
    }
    else {
        cout << "키 불러오기 에러" << endl;
    }
    uc Kt[16] = { 0 };
    for (int i = 0; i < 16; i++) {
        sscanf(kt_char + (i * 2), "%2hhx", &Kt[i]);
    }
    /*printf("Kt: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", Kt[i]);
    }*/
    _kf.close();
    // usersetup
    PrintUser();
    int num = 0;
    cin >> num;
    cin.ignore();
    string username;
    system("cls");
    if (num == 1) {
        cout << "================Register Page===============\n\n" << endl;

        cout << "I would like to know some information to setup. What is your name?";
        cout << ">>";
        cin >> username;
        cin.ignore();
        cout << "\nThanks, "<<username<< ". the user setup has perfectly done\n\n";
        cout << "============================================\n";
    }
    else if (num == 2) {
        cout << "=================LogIn Page================\n\n" << endl;

        cout << " * Please enter your username to log in *" << endl;
        cout << ">>";
        cin >> username;
        cin.ignore();
        cout << "\nHello, " << username << ". login successed !\n\n";

        cout << "============================================\n";
    }
    else {

    }
    try {
        // Boost.Asio를 사용하여 서버에 연결
        boost::asio::io_context io_context;
        tcp::socket socket(io_context);
        tcp::endpoint server_endpoint(asio::ip::make_address("127.0.0.1"), 12345); // Replace with the server's IP and port
        socket.connect(server_endpoint);

        while (1) {
            int Choice;
            PrintMenu();
            std::cout << ">>";

            if (!(std::cin >> Choice)) {
                std::cout << "\n잘 못 누르셨습니다. 다시 메뉴 페이지로 돌아갑니다.\n";
                std::cin.clear();   
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); 
                continue;   
            }
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            switch (Choice)
            {
                {
            case 1:
                cout << "============================================\n";

                string myfile;
                cout << "키워드 정보가 저장된 파일명을 알려주세요:";
                getline(cin, myfile);
                //bulid W
                string filename(myfile);
                unordered_set<string> keywords_set = Build_W(filename);
                //   Inverted Index File - Build IID (딕셔너리 형태)
                unordered_map<string, unordered_set<string>> IID = Build_IID(keywords_set);
                //   Build T (딕셔너리 형태)
                unordered_map<string, vector<uc>> T = Build_T(IID);
                TSetSetup(socket, T, keywords_set, 128, 128);

                cout << "Tset has been sent to server completely!" << endl;
                cout << "============================================\n";

                break;
                }
            case 2:
            {
                cout << "============================================\n";

                string myfile;
                cout << "업로드할 파일명을 알려주세요(확장자포함)";
                getline(cin, myfile);
                Store(myfile, socket);
                std::cout << "파일 암호화 해서 전송하기 완료" << endl;
                cout << "============================================\n";

                break;
            }
            case 3:
            {
                /*string username;
                cout << "유저 이름은?";
                cin >> username;
                cin.clear();*/
                cout << "============================================\n";

                string myword;
                cout << "문의하고 싶은 키워드는?";
                getline(cin, myword);
                Query_keyword(myword, Kt, socket);
                //Sleep(1000);

                Query_documents(socket, myword); //암호화된 파일아이디들 받고 복호화해서 재전송
                if (no_keyword == 1) {
                    no_keyword = 0;
                    break;
                }
                Restore(socket);
                if (no_keyword == 0) {
                    std::cout << "쿼리 보내고 다운로드 완료" << endl; //파일 있으면 보내고 아니면 못찾았다는 메세지 보냄
                    break;
                }
                cout << "============================================\n";

                break;
            }
            case 4:
            {
                cout << "할 일 다 끝나신 건가요? 안녕히 가세요 ;^)\n\n\n";
                socket.close();
                exit(1);
                break;
            }
            default:
                cout << "\n잘 못 누르셨습니다. 다시 메뉴 페이지로 돌아갑니다.\n";
                break;
            }
        }
        

    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
    
}