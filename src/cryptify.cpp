#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/secblock.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#if(defined(_WIN32)&&!defined(__CYGWIN__))
	#include <windows.h>
#else
	#include <termios.h>
	#include <unistd.h>
#endif

void stdin_echo(bool enable)
{
	#ifdef WIN32
		HANDLE hStdin=GetStdHandle(STD_INPUT_HANDLE);
		DWORD mode;
		GetConsoleMode(hStdin,&mode);
		if(!enable)
			mode&=~ENABLE_ECHO_INPUT;
		else
			mode|=ENABLE_ECHO_INPUT;
		SetConsoleMode(hStdin,mode);
	#else
		struct termios tty;
		tcgetattr(STDIN_FILENO,&tty);
		if(!enable)
			tty.c_lflag&=~ECHO;
		else
			tty.c_lflag|=ECHO;
		tcsetattr(STDIN_FILENO,TCSANOW,&tty);
	#endif
}

std::string get_password(const std::string& prompt)
{
	stdin_echo(false);
	std::string password;
	std::cout<<prompt<<std::flush;
	bool got_password=false;
	if(std::getline(std::cin,password)&&password.size()>0)
		got_password=true;
	stdin_echo(true);
	std::cout<<std::endl;
	if(!got_password)
		throw std::runtime_error("Empty passwords are not allowed.");
	return password;
}

bool file_to_string(const std::string& filename,std::string& data)
{
	char buffer;
	std::ifstream istr(filename.c_str(),std::ios_base::in|std::ios_base::binary);
	istr.unsetf(std::ios_base::skipws);
	if(!istr)
		return false;
	data="";
	while(istr>>buffer)
		data+=buffer;
	istr.close();
	return true;
}

bool string_to_file(const std::string& data,const std::string& filename)
{
	bool saved=false;
	std::ofstream ostr(filename.c_str(),std::ios_base::out|std::ios_base::binary);
	saved=(bool)(ostr<<data);
	ostr.close();
	return saved;
}

void encrypt(const CryptoPP::SecByteBlock& key,const std::string& in_path,const std::string& out_path)
{
	std::string plain;
	if(!file_to_string(in_path,plain))
		throw std::runtime_error("Could not read \""+in_path+"\".");

	std::string iv;
	std::string cipher;
	try
	{
		iv.resize(CryptoPP::AES::BLOCKSIZE);
		CryptoPP::AutoSeededRandomPool prng;
		prng.GenerateBlock((unsigned char*)iv.c_str(),CryptoPP::AES::BLOCKSIZE);

		CryptoPP::AES::Encryption encryptor((unsigned char*)key.data(),key.size());
		CryptoPP::CBC_Mode_ExternalCipher::Encryption cbc(encryptor,(unsigned char*)iv.c_str());
		CryptoPP::StreamTransformationFilter filter(cbc,new CryptoPP::StringSink(cipher));

		filter.Put((unsigned char*)plain.c_str(),plain.size());
		filter.MessageEnd();
	}
	catch(...)
	{
		throw std::runtime_error("Could not encrypt \""+in_path+"\".");
	}

	if(!string_to_file(iv+cipher,out_path))
		throw std::runtime_error("Could not write \""+out_path+"\".");
}

void decrypt(const CryptoPP::SecByteBlock& key,const std::string& in_path,const std::string& out_path)
{
	std::string cipher;
	if(!file_to_string(in_path,cipher))
		throw std::runtime_error("Could not read \""+in_path+"\".");

	std::string plain;
	try
	{
		if(cipher.size()<CryptoPP::AES::BLOCKSIZE)
			throw std::runtime_error("Bad file.");
		CryptoPP::AES::Decryption decryptor((unsigned char*)key.data(),key.size());
		CryptoPP::CBC_Mode_ExternalCipher::Decryption cbc(decryptor,(unsigned char*)cipher.c_str());
		CryptoPP::StreamTransformationFilter filter(cbc,new CryptoPP::StringSink(plain));
		filter.Put((unsigned char*)cipher.c_str()+CryptoPP::AES::BLOCKSIZE,cipher.size()-CryptoPP::AES::BLOCKSIZE);
		filter.MessageEnd();
	}
	catch(...)
	{
		throw std::runtime_error("Could not decrypt \""+in_path+"\".");
	}

	if(!string_to_file(plain,out_path))
		throw std::runtime_error("Could not write \""+out_path+"\".");
}

int main(int argc,char* argv[])
{
	try
	{
		if(argc!=4)
			throw std::runtime_error("Usage: "+std::string(argv[0])+" e|d INPUT_PATH OUTPUT_PATH");

		std::string mode=std::string(argv[1]);
		if(mode!="e"&&mode!="d")
			throw std::runtime_error("Invalid mode \""+mode+"\".");

		std::string password=get_password("Enter password: ");

		if(mode=="e")
		{
			std::string password_verify=get_password("Re-enter password: ");
			bool matches=(password==password_verify);
			if(!matches)
				throw std::runtime_error("Passwords do not match.");
		}

		CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
		CryptoPP::SecByteBlock key(32);
		kdf.DeriveKey((unsigned char*)key.data(),key.size(),0,(unsigned char*)password.c_str(),password.size(),NULL,0,15000);

		if(mode=="e")
			encrypt(key,argv[2],argv[3]);
		else
			decrypt(key,argv[2],argv[3]);
	}
	catch(std::exception& error)
	{
		std::cout<<"Error: "<<error.what()<<std::endl;
	}
	catch(...)
	{
		std::cout<<"Unknown error occurred."<<std::endl;
	}
	return 0;
}
