/*
    Copyright 2023 dragonflylee
*/

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <curl/curl.h>

namespace curlFuncs {
struct curlUpArgs {
    std::ifstream f;
    size_t size;
    uint64_t* o;
};

struct curlDlArgs {
    std::ofstream f;
    uint64_t* o;
};

}  // namespace curlFuncs

class http {
public:
    using Form = std::unordered_map<std::string, std::string>;

    http(const std::string& useragent = "JKSV");
    http(const http& other) = delete;
    ~http();

    static std::string encode_form(const Form& form);
    void set_headers(const std::vector<std::string>& headers);
    void set_ul_cb(uint64_t* o);
    void set_dl_cb(uint64_t* o);
    int get(const std::string& url, std::ostream* out);
    std::string put(const std::string& url, std::istream* data);
    std::string post(const std::string& url, const std::string& data);

private:
    static size_t easy_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata);
    static size_t easy_read_cb(char* ptr, size_t size, size_t nmemb, void* userdata);
    int perform(std::ostream* body);

    CURL* easy;
    struct curl_slist* chunk;
};
