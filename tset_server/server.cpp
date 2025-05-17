#define _CRT_SECURE_NO_WARNINGS
#include <string.h>
#include <stdlib.h>
#include <mysql.h>
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
typedef unsigned char AES_e[16];
const int HEADER_SIZE = 10;
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
void login_client() {
    MYSQL* mysql = mysql_init(NULL);
    if (mysql == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
    }
    if (mysql_real_connect(mysql, "127.0.0.1", "user1", "rkcjs1234", "tsettable", 3306, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed\n");
    }
    const char* insert_sql = "INSERT INTO client_ (name) VALUES (?)";
    MYSQL_STMT* stmt = mysql_stmt_init(mysql);
    if (stmt == NULL) {
        fprintf(stderr, "mysql_stmt_init() failed\n");
    }

    if (mysql_stmt_prepare(stmt, insert_sql, strlen(insert_sql)) != 0) {
        fprintf(stderr, "mysql_stmt_prepare() failed\n");
    }

    MYSQL_BIND bind_param[1];
    memset(bind_param, 0, sizeof(bind_param));

    char name[20] = "Alice"; // 클라이언트 이름
    bind_param[0].buffer_type = MYSQL_TYPE_VAR_STRING;
    bind_param[0].buffer = name;
    bind_param[0].buffer_length = strlen(name);

    if (mysql_stmt_bind_param(stmt, bind_param) != 0) {
        fprintf(stderr, "mysql_stmt_bind_param() failed\n");
    }

    if (mysql_stmt_execute(stmt) != 0) {
        fprintf(stderr, "mysql_stmt_execute() failed\n");
    }
    mysql_stmt_close(stmt);
    mysql_close(mysql);
}
void receive_file(tcp::socket& socket, vector<uc>& data) {
    vector<uc> buffer;
    buffer.reserve(8000);
    for (int i = 0; i < data.size(); i++)
        buffer.push_back(data[i]); // main에서 받은 페이로드 저장

    while (true) {
        boost::system::error_code error;

        string serializedPacket; //최대페이로드 1024바이트,헤더10바이트
        serializedPacket.resize(2048);
        size_t response_length = socket.read_some(asio::buffer(serializedPacket), error);
        std::cout << "response_length: " << response_length << std::endl;

        if (error == boost::asio::error::eof) {
            std::cout << "Client closed the connection." << std::endl;
            socket.close();
            break; // Exit the loop on client disconnect
        }
        else if (error) {
            std::cerr << "Error reading data: " << error.message() << std::endl;
            socket.close();
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
            payload_len= static_cast<int>(receivedPacket.header[0]) * 16 * 16 + static_cast<int>(receivedPacket.header[1]) * 16 + static_cast<int>(receivedPacket.header[2]);
            std::cout << "new payload len:" << payload_len << endl;
            is_new_packet = 0;
        }

        size_t rcvd_packet_len = receivedPacket.header.size() + receivedPacket.payload.size();
        cout << "rcvd_packet_len" << rcvd_packet_len << endl;

        if (payload_len == (rcvd_packet_len - HEADER_SIZE)) {
            vector<uint8_t> payload = receivedPacket.payload;
            is_new_packet = 1;
        }
        if (receivedPacket.header[5] == 7) {
            break; //종료알림
        }
        // Output debug information
        std::cout << "Header size: " << receivedPacket.header.size() << std::endl;
        std::cout << "Payload size: " << receivedPacket.payload.size() << std::endl;
        std::cout << "리시브드패킷: ";

        for (int i = 0; i < receivedPacket.payload.size(); i++) {
            buffer.push_back(receivedPacket.payload.at(i));
            printf("%02x", receivedPacket.payload[i]);
        }
    }
    printf("버퍼::");
    cout << "버퍼사이즈:" << buffer.size() << endl;
    for (int i = 0; i < buffer.size(); i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
    //버퍼에 파일내용 모두 씀->디비 저장
    MYSQL* mysql = mysql_init(NULL);
    if (mysql == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
    }
    if (mysql_real_connect(mysql, "127.0.0.1", "user1", "rkcjs1234", "tsettable", 3306, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed\n");
    }
    time_t timer;
    timer = time(NULL);
    struct tm* t = localtime(&timer);
    const char* insert_sql = "INSERT INTO file_ (contents, date_, client_id) VALUES (?,?,?)";
    MYSQL_STMT* stmt = mysql_stmt_init(mysql);
    if (stmt == NULL) {
        fprintf(stderr, "mysql_stmt_init() failed\n");
    }

    if (mysql_stmt_prepare(stmt, insert_sql, strlen(insert_sql)) != 0) {
        fprintf(stderr, "mysql_stmt_prepare() failed\n");
    }

    

    MYSQL_BIND bind_param[3];
    memset(bind_param, 0, sizeof(bind_param));

    bind_param[0].buffer_type = MYSQL_TYPE_BLOB;
    bind_param[0].buffer = &buffer[0]; // Use the address of the first element
    bind_param[0].buffer_length = buffer.size();
    cout << "buff.size()" << buffer.size() << endl;
    bind_param[0].is_null = 0;


    //날짜저장
    MYSQL_TIME mysql_date;
    mysql_date.year = t->tm_year + 1900;  // Set the year
    mysql_date.month = t->tm_mon + 1;   // Set the month
    mysql_date.day = t->tm_mday;
    bind_param[1].buffer_type = MYSQL_TYPE_DATE;
    bind_param[1].buffer = &mysql_date;
    bind_param[1].is_null = 0;

    int id = 1; // 클라이언트 넘버
    bind_param[2].buffer_type = MYSQL_TYPE_LONG;
    bind_param[2].buffer = &id;
    bind_param[2].is_unsigned = 1;

    if (mysql_stmt_bind_param(stmt, bind_param) != 0) {
        fprintf(stderr, "mysql_stmt_bind_param() failed\n");
    }

    if (mysql_stmt_execute(stmt) != 0) {
        fprintf(stderr, "mysql_stmt_execute() failed\n");
    }
    buffer.clear();
    mysql_stmt_close(stmt);
    mysql_close(mysql);
}
void receive_Tset(tcp::socket& socket, vector<uc>& data) {
    
    vector<uc> temp;
    temp.reserve(400000);
    temp.insert(temp.end(), data.begin(), data.end());  // main에서 받은 페이로드 저장
    std::cout << "tempsize:" << temp.size() << endl;
    while (true) {
        boost::system::error_code error;
        string serializedPacket; //최대페이로드 1024바이트,헤더10바이트
        serializedPacket.resize(2048); //받는버퍼 2048- 수정해야할수도
        size_t response_length = socket.read_some(asio::buffer(serializedPacket), error);
        std::cout << "response_length: " << response_length << std::endl;
        if (error == boost::asio::error::eof) {
            std::cout << "Client closed the connection." << std::endl;
            socket.close(); // 수정해야함 리트라이브쿼리 다 완성하면
            break; // Exit the loop on client disconnect
        }
        else if (error) {
            std::cerr << "Error reading data: " << error.message() << std::endl;
            socket.close();
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

        size_t rcvd_packet_len = receivedPacket.header.size() + receivedPacket.payload.size();
        cout << "rcvd_packet_len" << rcvd_packet_len << endl;

        if (payload_len == (rcvd_packet_len - HEADER_SIZE)) {
            vector<uint8_t> payload = receivedPacket.payload;
            is_new_packet = 1;
        }
        if (receivedPacket.header[5] == 7) {
            //전송완료됨
            break;
        }
        // Output debug information
        std::cout << "Header size: " << receivedPacket.header.size() << std::endl;
        std::cout << "Payload size: " << receivedPacket.payload.size() << std::endl;
        temp.insert(temp.end(), receivedPacket.payload.begin(), receivedPacket.payload.end());

    }
    cout << "temp.size()" << temp.size() << endl;
    MyPair** received_Tset; //티셋 포인터
    received_Tset = new MyPair * [128];
    for (int i = 0; i < 128; i++) {
        received_Tset[i] = new MyPair[128];
    }
    // Deserialization
    std::size_t offset = 0;
    for (int i = 0; i < 128; ++i) {
        for (int j = 0; j < 128; ++j) {
            std::memcpy(&received_Tset[i][j], &temp[offset], sizeof(MyPair));
            offset += sizeof(MyPair);
        }
    }

    //// 역직렬화된 데이터를 파일에 저장
    //std::ofstream ofs("received_Tset.bin", std::ios::binary);
    //for (int i = 0; i < 128; ++i) {
    //    for (int j = 0; j < 128; ++j) {
    //        ofs.write(reinterpret_cast<const char*>(&received_Tset[i][j]), sizeof(MyPair));
    //    }
    //}
    //ofs.close();
    // 역직렬화된 데이터를 디비에 저장
    MYSQL* mysql = mysql_init(NULL);
    if (mysql == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
    }
    if (mysql_real_connect(mysql, "127.0.0.1", "user1", "rkcjs1234", "tsettable", 3306, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed\n");
    }
    const char* insert_sql = "UPDATE client_ SET tset = (?) WHERE name = \'Alice\';";
    MYSQL_STMT* stmt = mysql_stmt_init(mysql);
    if (stmt == NULL) {
        fprintf(stderr, "mysql_stmt_init() failed\n");
    }

    if (mysql_stmt_prepare(stmt, insert_sql, strlen(insert_sql)) != 0) {
        fprintf(stderr, "mysql_stmt_prepare() failed\n");
    }

    std::vector<char> binaryData;
    binaryData.reserve(128 * 128 * sizeof(MyPair));

    for (int i = 0; i < 128; ++i) {
        for (int j = 0; j < 128; ++j) {
            const char* pairData = reinterpret_cast<const char*>(&received_Tset[i][j]);
            binaryData.insert(binaryData.end(), pairData, pairData + sizeof(MyPair));
        }
    }


    MYSQL_BIND bind_param[1];
    memset(bind_param, 0, sizeof(bind_param));

    bind_param[0].buffer_type = MYSQL_TYPE_BLOB;
    bind_param[0].buffer = binaryData.data();
    bind_param[0].buffer_length = binaryData.size();
    cout << "binaryData.size()" << binaryData.size() << endl;
    bind_param[0].is_null = 0;
     
    if (mysql_stmt_bind_param(stmt, bind_param) != 0) {
        fprintf(stderr, "mysql_stmt_bind_param() failed\n");
    }

    if (mysql_stmt_execute(stmt) != 0) {
        fprintf(stderr, "mysql_stmt_execute() failed\n");
    }
    binaryData.clear();
    mysql_stmt_close(stmt);
    mysql_close(mysql);


    // 역직렬화된 데이터 확인 및 출력
    cout << "역직렬화 후:" << endl;
    for (int i = 15; i < 65; ++i) {
        for (int j = 15; j < 64; ++j) {
            std::cout << "reTset[" << i << "][" << j << "].first: " << received_Tset[i][j].first.to_string() << std::endl;
            std::cout << "reTset[" << i << "][" << j << "].second: " << received_Tset[i][j].second.to_string() << std::endl;
        }
    }

    // 메모리 해지
    for (int i = 0; i < 128; ++i) {
        delete[] received_Tset[i];
    }
    delete[] received_Tset;

}
vector<uc> TsetRetrieve(MyPair** Tset, uc* stag) {
    vector<uc> V;
    int betta=1;
    uc i = 1;
    int terminate_iter = 0;  //해당 키워드 없으면 빨리 루프 빠져나오기 위함
    while (betta == 1) {
        
        terminate_iter++;
        uc iter_i[16] = { 0 };
        uc hash_input[16] = { 0 };
        for (int k = 0; k < 16; k++) {
            if (k == 0)
                iter_i[k] = i; //한 키워드에 255개의 id들있을수있음 그이상은안됨(왜냐면 uc로 id 정의해서, ppt상ok)
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

        terminate_iter = 0;
        for (int j = 1; j <= 128; j++) { // J임 헷갈리지말기
            cout << "Searching... Tset["<<b_decimal<<"]["<<j<<"].first" << Tset[b_decimal][j].first.to_string() << endl;
            if (Tset[b_decimal][j].first == L) {
                std::bitset<129> v_= Tset[b_decimal][j].second^K;
                betta = v_.test(128) ? 1 : 0;
                bitset<128> e_id_bit(v_.to_string().substr(1));
                std::vector<unsigned char> e_id;
                for (int i = 0; i < 16; ++i) {
                    std::bitset<8> eightBits(e_id_bit.to_string().substr(i * 8, 8));
                    e_id.push_back(static_cast<unsigned char>(eightBits.to_ulong()));
                }
                V.insert(V.end(), e_id.begin(), e_id.end());
            }
            else { 
                terminate_iter++;
                
            }
        }
        if (terminate_iter == 128) {
            cout << "no such keyword" << endl;
            V.push_back(1);
            return V; // 1개 임의의 데이터만 있는 벡터 - 존재하지않는키워드란 것을 전송 위함(파일하나라도있으면원소16개임)
        }
        i += 1;
    }
    
    return V;
}
void Answer_keyword(tcp::socket& socket, uc* stag) {
    cout << "in Answer_keyword func" << endl;

    MyPair** received_Tset; //티셋 포인터 선언
    received_Tset = new MyPair * [128];
    for (int i = 0; i < 128; i++) {
        received_Tset[i] = new MyPair[128];
    }

    //디비에서 티셋불러오기
    MYSQL* mysql = mysql_init(NULL);
    if (mysql == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
    }

    if (mysql_real_connect(mysql, "127.0.0.1", "user1", "rkcjs1234", "tsettable", 3306, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed\n");
    }

    const char* select_sql = "SELECT tset FROM client_ WHERE name='Alice'"; //앨리스의티셋을가져와라 - 하드코딩
    MYSQL_STMT* stmt = mysql_stmt_init(mysql);
    if (stmt == NULL) {
        fprintf(stderr, "mysql_stmt_init() failed\n");
    }

    if (mysql_stmt_prepare(stmt, select_sql, strlen(select_sql)) != 0) {
        fprintf(stderr, "mysql_stmt_prepare() failed\n");
    }

    MYSQL_BIND bind_result;
    memset(&bind_result, 0, sizeof(bind_result));

    std::vector<char> received_binary_data;  // 버퍼
    received_binary_data.resize(128 * 128 * sizeof(MyPair));

    bind_result.buffer_type = MYSQL_TYPE_BLOB;
    bind_result.buffer = received_binary_data.data();
    bind_result.buffer_length = received_binary_data.size();

    if (mysql_stmt_bind_result(stmt, &bind_result) != 0) {
        fprintf(stderr, "mysql_stmt_bind_result() failed\n");
    }

    if (mysql_stmt_execute(stmt) != 0) {
        fprintf(stderr, "mysql_stmt_execute() failed\n");
    }

    if (mysql_stmt_fetch(stmt) != 0) {
        fprintf(stderr, "mysql_stmt_fetch() failed\n");
    }

    mysql_stmt_close(stmt);


    // 티셋불러오기
    size_t offset = 0;
    for (int i = 0; i < 128; ++i) {
        for (int j = 0; j < 128; ++j) {
            memcpy(&received_Tset[i][j], received_binary_data.data() + offset, sizeof(MyPair));
            offset += sizeof(MyPair);
        }
    }
    //닫기
    mysql_close(mysql);
    received_binary_data.clear();

    //쿼리된 파일아이디들만 추출
    vector<uc> ptr = TsetRetrieve(received_Tset, stag);
    // 이제 티셋 메모리 해제
    for (int i = 0; i < 128; i++) {
        delete[] received_Tset[i]; 
    }
    delete[] received_Tset;

    cout << "sizeof(ptr):" << ptr.size() << endl;
    cout << "ptr:";
    for (int i = 0; i < ptr.size(); i++) {
        printf("%02x", ptr[i]);
    }
    //  클라이언트에게 패킷보내기

    Packet packet; //패킷최대페이로드는 1024
    packet.header.resize(10, 0); // 헤더크기만큼 일단 늘림
    packet.header[5] = 4; // 키워드에대한 답이라는뜻(명령)
    packet.header[4] = 1; //(is_new_file)

    size_t V_size = ptr.size();
    cout << "V_size: " << V_size << endl;
    size_t index = 0;
    while (V_size > 0) {
        if (V_size == 1) {
            packet.header[5] = 8;//->어짜피암호화된아이디들16배수이고페이로드크기도1024므로 홀수1만남을이유가없음
            //키워드에대응되는파일아이디들없다는명령
        }
        size_t payload_size = 0;
        for (int i = 0; i < V_size; i++) {
            if (payload_size == 1024) break;
            packet.payload.push_back(ptr[i + index]);
            payload_size++;
        }
        index += payload_size;
        V_size -= payload_size;

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
    if (ptr.size() > 1) { // 파일아이디들이 있었다면, 다 전송하고 종료한다는 패킷 보내줘야함
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
    }
    
}
void Answer_document(tcp::socket& socket, vector<uc>& data) {
    cout << "in Answer_document func" << endl;
    // data들에는 복호화된 파일아이디들 담김. 아마 패킷하나로 다 오기 가능할 것.(파일이1024개는아닐테니)
    std::unordered_set<int> myIDset;
    for (int i = 0; i < data.size(); i++) {
        myIDset.insert((int)data[i]);
    }
    cout << "myIDset확인출력";
    for (const auto& element : myIDset) {
        std::cout << element <<" ";
    }
    //DB에 파일 인포메이션 요청
    MYSQL* conn = mysql_init(NULL);

    if (conn == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
    }

    if (mysql_real_connect(conn, "127.0.0.1", "user1", "rkcjs1234", "tsettable", 3306, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed\n");
        mysql_close(conn);
    }
    std::cout << "DB Connection Success" << endl;
    char select_sql[1024];
    const char* username = "Alice"; //하드코딩
    sprintf_s(select_sql, sizeof(select_sql), "SELECT file_.id, file_.contents\nFROM(file_ JOIN client_ ON file_.client_id = client_.id)\nWHERE name = \"%s\"; ", username);

    if (mysql_real_query(conn, select_sql, strlen(select_sql)) != 0) {
        fprintf(stderr, "mysql_real_query() failed\n");
        mysql_close(conn);
    }

    MYSQL_RES* result = mysql_store_result(conn);
    
    while (MYSQL_ROW row = mysql_fetch_row(result))     // 모든 파일 탐색 ,row:각 열의 데이터가 문자열로 반환
    {
        cout << "row 루프 한번 돔" << endl;
        if (myIDset.count(atoi(row[0]))) {  //id가 아이디셋안에있다면,
            Packet packet; //패킷최대페이로드는 1024
            packet.header.resize(10, 0); // 헤더크기만큼 일단 늘림
            packet.header[5] = 6; //암호화된 파일 전송할테니 받으라는 뜻
            packet.header[4] = 1; //새로운 파일 업로드니까 파일열라는의미(is_new_file)

            unsigned char* blob_data = (unsigned char*)row[1];
            unsigned long* lengths = mysql_fetch_lengths(result);
            size_t blob_size = lengths[1]; // 블롭 데이터 사이즈
            cout << "blob_size " << blob_size << endl;
            size_t index = 0;
            while (blob_size > 0) {
                size_t payload_size = 0;
                for (int i = 0; i < blob_size; i++) {
                    if (payload_size == 1024) break;
                    packet.payload.push_back(blob_data[i + index]);
                    payload_size++;
                }
                index += payload_size;
                blob_size -= payload_size;

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
                Sleep(1000); //처리하고 다시 받을 때 까지 기다림

                // Output debug information
                std::cout << "Header size: " << packet.header.size() << std::endl;
                std::cout << "Payload size: " << packet.payload.size() << std::endl;

                packet.header[4] = 0; //이제 남은 데이터 보내면 됨(is_new_file==0)
                packet.payload.clear();
            }
        }
    }
    mysql_free_result(result);
    Packet packet; //패킷최대페이로드는 1024
    packet.header.resize(10, 0); // 헤더크기만큼 일단 늘림
    packet.header[5] = 7; // 모든 파일전송햇으니 소켓닫아도된다
    packet.header[2] = 1; // 페이로드크기:1 그냥 임의설정
    packet.payload.push_back(1);
    // Serialize the Packet
    std::ostringstream oss;
    boost::archive::binary_oarchive oa(oss);
    oa << packet;
    asio::write(socket, asio::buffer(oss.str()));

}
int main() {
    
    try {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::acceptor acceptor(io_context);
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(), 12345);
        acceptor.open(endpoint.protocol());
        acceptor.bind(endpoint);
        acceptor.listen(3);
        std::cout << "Server is listening on " << "HOST" << ":" << "PORT 12345" << std::endl;

        boost::asio::ip::tcp::socket socket(io_context);
        acceptor.accept(socket);

        cout << "A connection with a client was established" << endl;
        login_client();
        
        
        while (1) {

            boost::system::error_code error;
            string serializedPacket; // 최대 페이로드 1024바이트, 헤더 10바이트
            serializedPacket.resize(2000); // 받는 버퍼 2048 - 수정해야할 수도
            size_t response_length = socket.read_some(asio::buffer(serializedPacket), error);
            std::cout << "response_length: " << response_length << std::endl;
            if (error == boost::asio::error::eof) {
                std::cout << "Client closed the connection.(main loop)" << std::endl;
                socket.close();
                break; // Exit the loop on client disconnect
            }
            else if (error) {
                std::cerr << "Error reading data(main loop): " << error.message() << std::endl;
                socket.close();
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

            size_t rcvd_packet_len = receivedPacket.header.size() + receivedPacket.payload.size();
            cout << "rcvd_packet_len" << rcvd_packet_len << endl;

            if (payload_len == (rcvd_packet_len - HEADER_SIZE)) {
                vector<uint8_t> payload = receivedPacket.payload;
                is_new_packet = 1;
            }

            // Output debug information
            std::cout << "Header size: " << receivedPacket.header.size() << std::endl;
            std::cout << "Payload size: " << receivedPacket.payload.size() << std::endl;
            

            // Case
            if (receivedPacket.header[5] == 2) { // 명령이 store doc이라면
                receive_file(socket, receivedPacket.payload);
                //break;
            }
            if (receivedPacket.header[5] == 1) { // 명령이 store EDB라면
                receive_Tset(socket, receivedPacket.payload);
                //break;
            }
            if (receivedPacket.header[5] == 3) { // 명령이 Query:keyword라면(stag받는경우)
                uc stag[16];
                for (int i = 0; i < 16; i++)
                    stag[i]=receivedPacket.payload[i];
                Answer_keyword(socket, stag);
                Sleep(1500);
                //continue;
            }
            if (receivedPacket.header[5] == 5) {  // 명령이 Query:document라면(복호화된id받는경우)
                Answer_document(socket, receivedPacket.payload);
                //break;
            }
            if (receivedPacket.header[5] == 7) {
                cout << "클라이언트측에서 해당 키워드 파일 없다는 신호 받기 완료" << endl;
            }

        }
    }
    catch (exception& e) {
        cerr << "Error: " << e.what() << endl;
    }

    return 0;
}
