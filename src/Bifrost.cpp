#include <DiffieHellman.hpp>
#include <HMAC_SHA1.hpp>
#include <random.hpp>
#include <typedefs.hpp>
#include <utilities.hpp>

#include <ctime>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <cstdlib>

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;
namespace fs = std::filesystem;

// Read from environment variable — set LOGIN_SERVER_URL in Railway Variables.
// Falls back to localhost for local development.
string getServerUrl() {
    const char* env = std::getenv("LOGIN_SERVER_URL");
    return env ? string(env) : string("http://localhost:5000/signup/");
}

#define SECRET_KEY_FILE "shared_secret.txt"

string generateTOTP(Bytes key) {
    time_t timestamp = time(NULL);
    cpp_int timestep = timestamp / 30;
    Bytes message = resizeKey(cppIntToBytes(timestep), nBytes);
    Bytes hmac_bytes = hmac_sha1(key, message);
    int offset = hmac_bytes[hmac_bytes.size() - 1] & 0x0F;
    Bytes sample_bytes;
    for (int i = offset; i < offset + 4; i++) {
        sample_bytes.push_back(hmac_bytes[i]);
    }
    sample_bytes[0] &= 0x7f;
    cpp_int sample = bytesToCppInt(sample_bytes);
    int OTP = (sample % 1000000).convert_to<int>();
    string otp_string = to_string(OTP);
    while (otp_string.length() < 6) {
        otp_string = "0" + otp_string;
    }
    return otp_string;
}

Bytes exchangeSecret(string registrationCode) {
    Diffie_Hellman bifrostDH;
    string bifrostPublicKeyHex = cppIntToHex(bifrostDH.public_key);
    json requestBody;
    requestBody["bifrost-public-key"] = bifrostPublicKeyHex;

    string url = getServerUrl() + registrationCode;

    cout << "\nSending POST request to:\n" << url << endl;
    cout << "\nBifrost public key:\n" << bifrostPublicKeyHex << endl;

    cpr::Response response =
        cpr::Post(cpr::Url{url}, cpr::Body{requestBody.dump()},
                  cpr::Header{{"Content-Type", "application/json"}});

    if (response.error) {
        throw runtime_error(response.error.message);
    }
    if (response.status_code != 200) {
        cout << "\nServer response:\n" << response.text << endl;
        throw runtime_error("Server returned status code " +
                            to_string(response.status_code));
    }

    json responseJson = json::parse(response.text);
    if (!responseJson.contains("server-public-key")) {
        throw runtime_error("Response JSON does not contain server-public-key.");
    }

    Bytes serverPublicKey = hexToBytes(responseJson["server-public-key"]);
    Bytes sharedSecretKey =
        resizeKey(bifrostDH.compute_shared_secret(serverPublicKey), nBytes);

    cout << "\nBifrost public key:\n" << bifrostPublicKeyHex << endl;
    cout << "\nServer public key:\n" << bytesToHex(serverPublicKey) << endl;
    cout << "\nShared Secret key:\n" << bytesToHex(sharedSecretKey) << endl;
    return sharedSecretKey;
}

int main() {
    Bytes sharedSecretKey;

    if (fs::exists(SECRET_KEY_FILE)) {
        ifstream saved_file(SECRET_KEY_FILE);
        if (!saved_file) {
            throw runtime_error("couldn't open shared_secret.txt");
        }
        string loaded_secret;
        getline(saved_file, loaded_secret);
        saved_file.close();
        sharedSecretKey = resizeKey(hexToBytes(loaded_secret), nBytes);
    } else {
        try {
            string registrationCode;
            cout << "Enter 6-digit registration code: ";
            cin >> registrationCode;

            if (registrationCode.length() != 6) {
                throw runtime_error("Registration code must be 6 digits.");
            }

            sharedSecretKey = exchangeSecret(registrationCode);
            string sharedSecret_hex = bytesToHex(sharedSecretKey);

            ofstream file(SECRET_KEY_FILE);
            if (!file) {
                throw runtime_error("Could not create shared_secret.txt");
            }
            file << sharedSecret_hex;
            file.close();
            cout << "\nShared secret saved in shared_secret.txt" << endl;
        } catch (const exception &e) {
            cerr << "\nError: " << e.what() << endl;
            return 1;
        }
    }

    string otp = generateTOTP(sharedSecretKey);
    cout << "\nGenerated OTP: " << otp << endl;
    int timeLeft = 30 - (time(NULL) % 30);
    cout << "Valid for: " << timeLeft << "s" << endl;

    return 0;
}
