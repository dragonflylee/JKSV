#include "http.h"
#include <sstream>

#ifndef CURL_PROGRESSFUNC_CONTINUE
#define CURL_PROGRESSFUNC_CONTINUE 0x10000001
#endif

/// @brief curl context

http::http(const std::string& useragent) : chunk(nullptr) {
    this->easy = curl_easy_init();

    curl_easy_setopt(this->easy, CURLOPT_USERAGENT, useragent.c_str());
    curl_easy_setopt(this->easy, CURLOPT_FOLLOWLOCATION, 1L);
    // enable all supported built-in compressions
    curl_easy_setopt(this->easy, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(this->easy, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(this->easy, CURLOPT_SSL_VERIFYPEER, 0L);
}

http::~http() {
    if (this->chunk != nullptr) curl_slist_free_all(this->chunk);
    if (this->easy != nullptr) curl_easy_cleanup(this->easy);
}

void http::set_headers(const std::vector<std::string>& headers) {
    if (this->chunk != nullptr) {
        curl_slist_free_all(this->chunk);
        this->chunk = nullptr;
    }
    for (auto& h : headers) {
        this->chunk = curl_slist_append(this->chunk, h.c_str());
    }
    curl_easy_setopt(this->easy, CURLOPT_HTTPHEADER, this->chunk);
}

size_t http::easy_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::ostream* ctx = reinterpret_cast<std::ostream*>(userdata);
    size_t count = size * nmemb;
    ctx->write(ptr, static_cast<std::streamsize>(count));
    return count;
}

size_t http::easy_read_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::istream* ctx = reinterpret_cast<std::istream*>(userdata);
    size_t count = size * nmemb;
    ctx->read(ptr, static_cast<std::streamsize>(count));
    return ctx->gcount();
}

static int easy_dl_cb(void* clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
    uint64_t* ctx = reinterpret_cast<uint64_t*>(clientp);
    *ctx = dlnow;
    return CURL_PROGRESSFUNC_CONTINUE;
}

static int easy_ul_cb(void* clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
    uint64_t* ctx = reinterpret_cast<uint64_t*>(clientp);
    *ctx = ulnow;
    return CURL_PROGRESSFUNC_CONTINUE;
}

void http::set_ul_cb(uint64_t* o) {
    curl_easy_setopt(this->easy, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(this->easy, CURLOPT_XFERINFOFUNCTION, easy_ul_cb);
    curl_easy_setopt(this->easy, CURLOPT_XFERINFODATA, o);
}

void http::set_dl_cb(uint64_t* o) {
    curl_easy_setopt(this->easy, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(this->easy, CURLOPT_XFERINFOFUNCTION, easy_dl_cb);
    curl_easy_setopt(this->easy, CURLOPT_XFERINFODATA, o);
}

int http::perform(std::ostream* body) {
    curl_easy_setopt(this->easy, CURLOPT_WRITEFUNCTION, easy_write_cb);
    curl_easy_setopt(this->easy, CURLOPT_WRITEDATA, body);

    CURLcode res = curl_easy_perform(this->easy);
    if (res != CURLE_OK) {
        body->clear();
        return res;
    }
    int status_code = 0;
    curl_easy_getinfo(this->easy, CURLINFO_RESPONSE_CODE, &status_code);
    return status_code;
}

std::string http::encode_form(const Form& form) {
    std::ostringstream ss;
    char* escaped;
    for (auto it = form.begin(); it != form.end(); ++it) {
        if (it != form.begin()) ss << '&';
        escaped = curl_escape(it->second.c_str(), it->second.size());
        ss << it->first << '=' << escaped;
        curl_free(escaped);
    }
    return ss.str();
}

int http::get(const std::string& url, std::ostream* out) {
    curl_easy_setopt(this->easy, CURLOPT_URL, url.c_str());
    curl_easy_setopt(this->easy, CURLOPT_HTTPGET, 1L);
    return this->perform(out);
}

std::string http::put(const std::string& url, std::istream* data) {
    std::ostringstream body;
    curl_easy_setopt(this->easy, CURLOPT_URL, url.c_str());
    curl_easy_setopt(this->easy, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(this->easy, CURLOPT_READFUNCTION, easy_read_cb);
    curl_easy_setopt(this->easy, CURLOPT_READDATA, data);
    this->perform(&body);
    return body.str();
}

std::string http::post(const std::string& url, const std::string& data) {
    std::ostringstream body;
    curl_easy_setopt(this->easy, CURLOPT_URL, url.c_str());
    curl_easy_setopt(this->easy, CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(this->easy, CURLOPT_POSTFIELDSIZE, data.size());
    this->perform(&body);
    return body.str();
}