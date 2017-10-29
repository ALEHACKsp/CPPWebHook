#include <string>

#include <iostream>
#include <chrono>

#include "include/modes.h"
#include "include/aes.h"
#include "include/filters.h"
#include "include/osrng.h"
#include "include/base64.h"
#include "include/rsa.h"

#include "include/curl.h"

#include "include/json.hpp"

using json = nlohmann::json;

struct MemoryStruct {
	char *memory;
	size_t size;
};

static void replaceAll(std::string& str, const std::string& from, const std::string& to) {
	if (from.empty())
		return;
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
	}
}

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	mem->memory = reinterpret_cast<char*>(realloc(mem->memory, mem->size + realsize + 1));
	if (mem->memory == NULL) {
		/* out of memory! */
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

static std::string string_to_hex(const std::string& input)
{
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();

	std::string output;
	output.reserve(2 * len);
	for (size_t i = 0; i < len; ++i)
	{
		const unsigned char c = input[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}
	return output;
}

static std::string RunWebHook(const std::string aesKey, const std::string hash, const std::string userId, const std::string command, std::string url) 
{
	std::string commandResult;
	const size_t AES_KEY_LENGTH = 32;
	CURL *curl_handle;
	CURLcode res;
	struct MemoryStruct chunk;
	chunk.memory = reinterpret_cast<char*>(malloc(1));
	chunk.size = 0; 
	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
	CryptoPP::AutoSeededRandomPool rnd;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
	byte iv[CryptoPP::AES::BLOCKSIZE];
	rnd.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);
	std::string decodedAesKey;
	CryptoPP::Base64Decoder decoderForAesKey;
	decoderForAesKey.Put((byte*)aesKey.data(), aesKey.size());
	decoderForAesKey.MessageEnd();
	CryptoPP::word64 sizeOfAesKey = decoderForAesKey.MaxRetrievable();
	if (sizeOfAesKey && sizeOfAesKey <= SIZE_MAX)
	{
		decodedAesKey.resize(sizeOfAesKey);
		decoderForAesKey.Get((byte*)decodedAesKey.data(), decodedAesKey.size());
	}

	encryptor.SetKeyWithIV((byte*)decodedAesKey.data(), AES_KEY_LENGTH, iv);
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
	decryptor.SetKeyWithIV((byte*)decodedAesKey.data(), AES_KEY_LENGTH, iv);
	size_t aesSecMessageLen = hash.length() + 16 - (hash.length() % 16);
	std::string encryptedSecMessage;
	CryptoPP::StringSource(hash, true,
		new CryptoPP::StreamTransformationFilter(encryptor, new CryptoPP::StringSink(encryptedSecMessage),
			CryptoPP::StreamTransformationFilter::PKCS_PADDING));
	CryptoPP::Base64Encoder encoderForEM;
	encoderForEM.Put((byte*)encryptedSecMessage.data(), aesSecMessageLen);
	encoderForEM.MessageEnd();
	std::string encodedEM;
	CryptoPP::word64 sizeEM = encoderForEM.MaxRetrievable();
	if (sizeEM)
	{
		encodedEM.resize(sizeEM);
		encoderForEM.Get((byte*)encodedEM.data(), encodedEM.size());
	}

	CryptoPP::Base64Encoder encoderForIV;
	encoderForIV.Put(iv, 16);
	encoderForIV.MessageEnd();
	std::string encodedIV;
	CryptoPP::word64 sizeIV = encoderForIV.MaxRetrievable();
	if (sizeIV)
	{
		encodedIV.resize(sizeIV);
		encoderForIV.Get((byte*)encodedIV.data(), encodedIV.size());
	}

	std::string rinside = hash + encodedIV.substr(0, 13);
	std::replace(encodedEM.begin(), encodedEM.end(), '=', '$');
	std::replace(encodedIV.begin(), encodedIV.end(), '=', '$');
	replaceAll(encodedEM, "+", "%2B");
	replaceAll(encodedIV, "+", "%2B");
	std::string query = "obj=command=sec*id="+ userId +"*em=" + encodedEM + "*m="+ encodedIV +"&rct=application/json";
	curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, query.c_str());
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	res = curl_easy_perform(curl_handle);
	if (res != CURLE_OK) {
		std::string error = curl_easy_strerror(res);
		curl_easy_cleanup(curl_handle);
		free(chunk.memory);
		curl_global_cleanup();
		return "{\"error\":\""+ error + "\"}";
	}
	else {
		//printf("%lu bytes retrieved\n", (long)chunk.size);
		std::string serverPublicRsaKey = chunk.memory;
		curl_easy_cleanup(curl_handle);
		free(chunk.memory);
		chunk.memory = reinterpret_cast<char*>(malloc(1));
		chunk.size = 0;  
		curl_handle = curl_easy_init();
		curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
		auto json = json::parse(serverPublicRsaKey);
		std::string modulus = json["m"];
		CryptoPP::Base64Decoder decoderPK;
		decoderPK.Put((byte*)modulus.data(), modulus.size());
		decoderPK.MessageEnd();
		CryptoPP::word64 sizePK = decoderPK.MaxRetrievable();
		byte b64_pkey[144];
		if (sizePK && sizePK <= SIZE_MAX)
		{
			decoderPK.Get(b64_pkey, sizePK);
		}

		std::string hexModulus;
		CryptoPP::ArraySource(b64_pkey,sizePK,true,
			new CryptoPP::StreamTransformationFilter(decryptor, new CryptoPP::StringSink(hexModulus),
				CryptoPP::StreamTransformationFilter::PKCS_PADDING));
		hexModulus = "0x" + hexModulus;
		CryptoPP::Integer nModulus(hexModulus.c_str());
		CryptoPP::Integer nExponent("0x10001");
		CryptoPP::RSA::PublicKey pubKey;
		pubKey.Initialize(nModulus, nExponent);
		CryptoPP::RSAES_PKCS1v15_Encryptor rsaEnc(pubKey);
		std::string strCipherTextRSA;
		CryptoPP::StringSource ss1(rinside, true,
			new CryptoPP::PK_EncryptorFilter(rnd, rsaEnc,
				new CryptoPP::StringSink(strCipherTextRSA)
			) 
		); 
		size_t messageLen2 = command.length() + 16 - (command.length() % 16);
		std::string encryptedCommand;
		encryptor.SetKeyWithIV((byte*)decodedAesKey.data(), AES_KEY_LENGTH, iv);
		CryptoPP::StringSource(command, true,
			new CryptoPP::StreamTransformationFilter(encryptor, new CryptoPP::StringSink(encryptedCommand),
				CryptoPP::StreamTransformationFilter::PKCS_PADDING));
		CryptoPP::Base64Encoder encoderForEM2;
		encoderForEM2.Put((byte*)encryptedCommand.data(), messageLen2);
		encoderForEM2.MessageEnd();
		std::string encodedEM2;
		CryptoPP::word64 sizeEM2 = encoderForEM2.MaxRetrievable();
		if (sizeEM2)
		{
			encodedEM2.resize(sizeEM2);
			encoderForEM2.Get((byte*)encodedEM2.data(), encodedEM2.size());
		}

		std::replace(encodedEM2.begin(), encodedEM2.end(), '=', '$');
		std::replace(modulus.begin(), modulus.end(), '=', '$');
		replaceAll(encodedEM2, "+", "%2B");
		replaceAll(modulus, "+", "%2B");
		std::string query = "obj=command="+ encodedEM +"*id="+ userId +"*c=" + modulus + "*r=" + string_to_hex(strCipherTextRSA) + "*l="+ encodedIV +"&rct=application/json";
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, query.c_str());
		res = curl_easy_perform(curl_handle);
		if (res != CURLE_OK) {
			std::string error = curl_easy_strerror(res);
			curl_easy_cleanup(curl_handle);
			free(chunk.memory);
			curl_global_cleanup();
			return "{\"error\":\"" + error + "\"}";
		}
		else {
			//printf("%lu bytes retrieved\n", (long)chunk.size);
			commandResult = chunk.memory;
			auto json = json::parse(commandResult);
			std::string encryptedCommandResult = json["result"];
			decryptor.SetKeyWithIV((byte*)decodedAesKey.data(), AES_KEY_LENGTH, iv);
			std::string decryptedComandResult;
			CryptoPP::Base64Decoder decoderForResult;
			decoderForResult.Put((byte*)encryptedCommandResult.data(), encryptedCommandResult.size());
			decoderForResult.MessageEnd();
			CryptoPP::word64 sizeForResult = decoderForResult.MaxRetrievable();
			std::unique_ptr<byte[]> binaryEncryptedResult(new byte[sizeForResult]);
			if (sizeForResult && sizeForResult <= SIZE_MAX)
			{
				decoderForResult.Get(binaryEncryptedResult.get(), sizeForResult);
			}

			CryptoPP::ArraySource(binaryEncryptedResult.get(), sizeForResult, true,
				new CryptoPP::StreamTransformationFilter(decryptor, new CryptoPP::StringSink(decryptedComandResult),
					CryptoPP::StreamTransformationFilter::PKCS_PADDING));

			commandResult = decryptedComandResult;
		}
	}

	curl_easy_cleanup(curl_handle);
	free(chunk.memory);
	curl_global_cleanup();
	return commandResult;
}

int main()
{
    printf("hello from WebHookAbility!\n");	
	auto start_time = std::chrono::high_resolution_clock::now();
	// Sample is using admin credentials (development mode) - guid is not needed for webhook communication, it can be still used on http server side from javascript (ViewApp)
	std::string result = RunWebHook("Idq1DzSPRjcLuyK9kF/HQ9rTUqqWD4GYqO3L4iwL0Ek=", "f350f31634532f5e6b18eef457cfbad718a5ec65", "9c0fed26868e4f180751cca3c67908e65d3ceab8c2c4a53872d9ffc778399264", "bad_command", "http://192.168.116.2/pass");
	auto end_time = std::chrono::high_resolution_clock::now();
	auto time = end_time - start_time;
	std::cout << "webhook request took: " <<
		std::chrono::duration_cast<std::chrono::milliseconds>(time).count() << " milliseconds to run.\n";
	return 0;
}