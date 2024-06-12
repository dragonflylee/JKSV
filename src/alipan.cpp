#include "alipan.h"
#include "http.h"
#include "util.h"
#include "cfg.h"
#include <switch.h>
#include <fstream>
#include <filesystem>
#include <algorithm>

#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>

namespace drive {

const std::string ALIPAN_PRE_AUTH = "https://auth.alipan.com/v2/oauth/authorize?";
const std::string ALIPAN_CALLBACK = "https://www.alipan.com/sign/callback";
const std::string ALIPAN_CANARY = "X-Canary: client=windows,app=adrive,version=v4.12.0";
const std::string ALIPAN_REFERER = "Referer: https://www.alipan.com/";

alipan::~alipan() {}

bool alipan::tokenIsValid() {
    if (!this->signature.empty()) return true;

    if (!this->accessToken.empty()) {
        if (this->getSelfuser()) return true;
    } else if (!cfg::driveRefreshToken.empty()) {
        if (this->refreshToken()) return true;
    }

    if (cfg::driveClientID.empty()) {  // 1. 计算设备ID
        AccountUid uid;
        uint8_t digest[32];
        if (R_FAILED(accountGetPreselectedUser(&uid))) {
            if (R_FAILED(accountTrySelectUserWithoutInteraction(&uid, false))) {
                accountGetLastOpenedUser(&uid);
            }
        }
        if (accountUidIsValid(&uid)) {
            sha256CalculateHash(digest, &uid, sizeof(uid));
        } else {
            randomGet(digest, sizeof(digest));
        }
        cfg::driveClientID = util::hexEncode(digest, sizeof(digest));
    }

    // 2. Open Browser
    WebCommonConfig webCfg;
    WebCommonReply webReply;
    std::string query = http::encode_form({
        {"login_type", "custom"},
        {"response_type", "code"},
        {"redirect_uri", ALIPAN_CALLBACK},
        {"client_id", "25dzX3vbYqktVxyX"},
        {"sid", std::to_string(time(nullptr))},
        {"state", "{\"origin\":\"file://\"}"},
    });
    std::string url = ALIPAN_PRE_AUTH + query;

    webPageCreate(&webCfg, url.c_str());
    webConfigSetFooter(&webCfg, false);
    webConfigSetPointer(&webCfg, false);
    webConfigSetPageCache(&webCfg, false);
    webConfigSetJsExtension(&webCfg, true);
    webConfigSetUserAgentAdditionalString(&webCfg, "aDrive/4.12.0");
    webConfigSetCallbackUrl(&webCfg, ALIPAN_CALLBACK.c_str());
    if (R_FAILED(webConfigShow(&webCfg, &webReply))) return false;

    size_t lastUrlLen = 0;
    std::string lastUrl(1024, '\0');
    if (R_FAILED(webReplyGetLastUrl(&webReply, lastUrl.data(), lastUrl.size(), &lastUrlLen))) return false;
    lastUrl.resize(lastUrlLen);

    int pos = lastUrl.find("?code=") + 6;
    int end = lastUrl.find_first_of('&', pos);
    if (pos < end) query = lastUrl.substr(pos, end - pos);

    // 3. GetToken
    SetSysDeviceNickName nick;
    json_object* post = json_object_new_object();
    json_object_object_add(post, "code", json_object_new_string(query.c_str()));
    json_object_object_add(post, "loginType", json_object_new_string("normal"));
    json_object_object_add(post, "deviceId", json_object_new_string(cfg::driveClientID.c_str()));
    if (R_SUCCEEDED(setsysGetDeviceNickname(&nick))) {
        json_object_object_add(post, "deviceName", json_object_new_string(nick.nickname));
    }
    json_object_object_add(post, "modelName", json_object_new_string("Windows客户端"));
    query = json_object_get_string(post);
    json_object_put(post);

    json_object* resp = this->request("/token/get", query);
    if (!resp) return false;

    json_object* value;
    if (json_object_object_get_ex(resp, "access_token", &value)) {
        this->accessToken = json_object_get_string(value);
    }
    if (json_object_object_get_ex(resp, "refresh_token", &value)) {
        cfg::driveRefreshToken = json_object_get_string(value);
    }
    if (json_object_object_get_ex(resp, "user_id", &value)) {
        this->userId = json_object_get_string(value);
    }
    if (json_object_object_get_ex(resp, "default_drive_id", &value)) {
        this->driveId = json_object_get_string(value);
    }
    json_object_put(post);
    printf("login user_id(%s) drive_id(%s)\n", this->userId.c_str(), this->driveId.c_str());

    return this->createSession();
}

void alipan::driveListInit(const std::string& _q) {
    json_object* post = json_object_new_object();
    json_object_object_add(post, "drive_id", json_object_new_string(this->driveId.c_str()));
    json_object_object_add(post, "parent_file_id", json_object_new_string(_q.c_str()));
    json_object_object_add(post, "limit", json_object_new_int(200));
    json_object_object_add(post, "all", json_object_new_boolean(false));
    json_object_object_add(post, "url_expire_sec", json_object_new_int(14400));
    json_object_object_add(post, "image_thumbnail_process", json_object_new_string("image/resize,w_256/format,jpeg"));
    json_object_object_add(
        post, "image_url_process", json_object_new_string("image/resize,w_1920/format,jpeg/interlace,1"));
    json_object_object_add(post, "fields", json_object_new_string("*"));
    json_object_object_add(post, "order_by", json_object_new_string("updated_at"));
    json_object_object_add(post, "order_direction", json_object_new_string("DESC"));

    json_object* resp = this->request("/adrive/v3/file/list", json_object_get_string(post));
    json_object_put(post);
    if (!resp) return;

    json_object* items = nullptr;
    if (json_object_object_get_ex(resp, "items", &items)) {
        json_object* value = nullptr;
        size_t len = json_object_array_length(items);
        for (size_t i = 0; i < len; i++) {
            drive::gdItem newItem;
            json_object* it = json_object_array_get_idx(items, i);
            if (json_object_object_get_ex(it, "name", &value)) {
                newItem.name = json_object_get_string(value);
            }
            if (json_object_object_get_ex(it, "file_id", &value)) {
                newItem.id = json_object_get_string(value);
            }
            if (json_object_object_get_ex(it, "parent_file_id", &value)) {
                newItem.parent = json_object_get_string(value);
            }
            if (json_object_object_get_ex(it, "size", &value)) {
                newItem.size = json_object_get_uint64(value);
            }
            if (json_object_object_get_ex(it, "type", &value)) {
                newItem.isDir = !strcmp(json_object_get_string(value), "folder");
            }
            this->driveList[newItem.id] = newItem;
        }
    }

    json_object_put(resp);
}

std::string alipan::createDir(const std::string& _dirName, const std::string& _parent) {
    std::string name = _dirName;
    name.erase(std::remove(name.begin(), name.end(), ':'), name.end());
    json_object* post = json_object_new_object();
    json_object_object_add(post, "drive_id", json_object_new_string(this->driveId.c_str()));
    json_object_object_add(post, "parent_file_id", json_object_new_string(_parent.c_str()));
    json_object_object_add(post, "name", json_object_new_string(name.c_str()));
    json_object_object_add(post, "type", json_object_new_string("folder"));
    json_object_object_add(post, "check_name_mode", json_object_new_string("refuse"));

    json_object* resp = this->request("/adrive/v2/file/createWithFolders", json_object_get_string(post));
    json_object_put(post);

    if (!resp) {
        printf("createDir `%s` failed\n", _dirName.c_str());
        return "";
    }

    json_object* id;
    drive::gdItem newDir;
    newDir.name = name;
    if (json_object_object_get_ex(resp, "file_id", &id)) {
        newDir.id = json_object_get_string(id);
    }
    newDir.isDir = true;
    newDir.parent = _parent;
    this->driveList[newDir.id] = newDir;

    json_object_put(resp);
    return newDir.id;
}

std::string alipan::getDirID(const std::string& _name, const std::string& _parent) {
    std::string name = _name;
    name.erase(std::remove(name.begin(), name.end(), ':'), name.end());
    return gd::getDirID(name, _parent);
}

bool alipan::deleteFile(const std::string& _fileID) {
    json_object* post = json_object_new_object();
    json_object_object_add(post, "drive_id", json_object_new_string(this->driveId.c_str()));
    json_object_object_add(post, "file_id", json_object_new_string(_fileID.c_str()));

    json_object* resp = this->request("/v2/recyclebin/trash", json_object_get_string(post));
    json_object_put(post);
    json_object_put(resp);

    this->driveList.erase(_fileID);
    return true;
}

void alipan::uploadFile(const std::string& _filename, const std::string& _parent, curlFuncs::curlUpArgs* _upload) {
    json_object* post = json_object_new_object();
    json_object* parts = json_object_new_array();
    json_object* info = json_object_new_object();
    json_object_object_add(info, "part_number", json_object_new_int(1));
    json_object_array_add(parts, info);
    json_object_object_add(post, "drive_id", json_object_new_string(this->driveId.c_str()));
    json_object_object_add(post, "part_info_list", parts);
    json_object_object_add(post, "parent_file_id", json_object_new_string(_parent.c_str()));
    json_object_object_add(post, "name", json_object_new_string(_filename.c_str()));
    json_object_object_add(post, "size", json_object_new_uint64(_upload->size));
    json_object_object_add(post, "type", json_object_new_string("file"));
    json_object_object_add(post, "check_name_mode", json_object_new_string("refuse"));
    json_object_object_add(post, "create_scene", json_object_new_string("file_upload"));
    json_object_object_add(post, "content_hash_name", json_object_new_string("none"));
    json_object_object_add(post, "proof_version", json_object_new_string("v1"));

    json_object* resp = this->request("/adrive/v2/file/createWithFolders", json_object_get_string(post));
    json_object_put(post);
    if (!resp) return;
    // upload part
    json_object* value;
    http c("Mozilla/5.0 aDrive/4.12.0");
    c.set_ul_cb(_upload->o);
    if (json_object_object_get_ex(resp, "part_info_list", &parts)) {
        size_t len = json_object_array_length(parts);
        for (size_t i = 0; i < len; i++) {
            info = json_object_array_get_idx(parts, i);
            json_object_object_get_ex(info, "upload_url", &value);
            std::string r = c.put(json_object_get_string(value), &_upload->f);
            if (!r.empty()) printf("upload part failed: %s\n", r.c_str());
        }
    }
    // complete upload
    post = json_object_new_object();
    json_object_object_add(post, "drive_id", json_object_new_string(this->driveId.c_str()));
    if (json_object_object_get_ex(resp, "file_id", &value)) {
        json_object_get(value);
        json_object_object_add(post, "file_id", value);
    }
    if (json_object_object_get_ex(resp, "upload_id", &value)) {
        json_object_get(value);
        json_object_object_add(post, "upload_id", value);
    }
    json_object_put(resp);

    resp = this->request("/v2/file/complete", json_object_get_string(post));
    json_object_put(post);
    if (!resp) return;

    drive::gdItem newItem;
    newItem.name = _filename;
    if (json_object_object_get_ex(resp, "file_id", &value)) {
        newItem.id = json_object_get_string(value);
    }
    newItem.parent = _parent;
    this->driveList[newItem.id] = newItem;
    json_object_put(resp);
}

bool alipan::downloadFile(const std::string& _fileID, curlFuncs::curlDlArgs* _download) {
    json_object* post = json_object_new_object();
    json_object_object_add(post, "drive_id", json_object_new_string(this->driveId.c_str()));
    json_object_object_add(post, "file_id", json_object_new_string(_fileID.c_str()));
    json_object_object_add(post, "expire_sec", json_object_new_int(14400));
    json_object* resp = this->request("/v2/file/get_download_url", json_object_get_string(post));
    json_object_put(post);
    if (!resp) return false;

    json_object* value;
    http c("Mozilla/5.0 aDrive/4.12.0");
    c.set_dl_cb(_download->o);
    c.set_headers({
        ALIPAN_REFERER,
        ALIPAN_CANARY,
        HEADER_AUTHORIZATION + this->accessToken,
        "X-Device-Id: " + cfg::driveClientID,
    });

    if (json_object_object_get_ex(resp, "url", &value)) {
        const char *url = json_object_get_string(value);
        int status = c.get(url, &_download->f);
        printf("download %d: %s\n", status, url);
        if (status == 200) {
            _download->f.flush();
        }
    }
    json_object_put(resp);
    return true;
}

json_object* alipan::request(const std::string& api, const std::string& data) {
    http s("Mozilla/5.0 aDrive/4.12.0");
    while (true) {
        std::vector<std::string> headers = {
            HEADER_CONTENT_TYPE_APP_JSON,
            ALIPAN_REFERER,
            ALIPAN_CANARY,
        };
        if (this->accessToken.size() > 0) {
            headers.push_back(HEADER_AUTHORIZATION + this->accessToken);
        }
        if (cfg::driveClientID.size() > 0) {
            headers.push_back("X-Device-Id: " + cfg::driveClientID);
        }
        if (this->signature.size() > 0) {
            headers.push_back("X-Signature: " + this->signature);
        }
        s.set_headers(headers);
        std::string resp = s.post("https://api.alipan.com" + api, data);
        json_object* data = json_tokener_parse(resp.c_str());
        if (!data) return nullptr;

        json_object* code = json_object_object_get(data, "code");
        if (!code) return data;

        const char* codeStr = json_object_get_string(code);
        if (!codeStr) return data;

        if (strcmp(codeStr, "AccessTokenInvalid") == 0) {
            this->refreshToken();
        } else if (strcmp(codeStr, "DeviceSessionSignatureInvalid") == 0) {
            this->createSession();
        } else {
            json_object_put(data);
            printf("request `%s` => %s\n", api.c_str(), resp.c_str());
            return nullptr;
        }
    }
}

bool alipan::getSelfuser() {
    json_object* resp = this->request("/v2/user/get", "{}");
    if (!resp) return false;

    json_object* value = nullptr;
    if (json_object_object_get_ex(resp, "user_id", &value)) {
        this->userId = json_object_get_string(value);
    }
    if (json_object_object_get_ex(resp, "default_drive_id", &value)) {
        this->driveId = json_object_get_string(value);
    }
    json_object_put(resp);

    return this->signature.empty() ? this->createSession() : true;
}

bool alipan::refreshToken() {
    http s;
    s.set_headers({"Content-Type: application/json", "x-requested-with: XMLHttpRequest"});

    json_object* post = json_object_new_object();
    json_object_object_add(post, "refresh_token", json_object_new_string(cfg::driveRefreshToken.c_str()));
    json_object_object_add(post, "grant_type", json_object_new_string("refresh_token"));
    std::string body = s.post("https://auth.alipan.com/v2/account/token", json_object_get_string(post));
    json_object_put(post);

    json_object* value = nullptr;
    json_object* resp = json_tokener_parse(body.c_str());
    if (json_object_object_get_ex(resp, "refresh_token", &value)) {
        cfg::driveRefreshToken = json_object_get_string(value);
    }
    if (json_object_object_get_ex(resp, "access_token", &value)) {
        this->accessToken = json_object_get_string(value);
    }
    json_object_put(resp);

    return this->createSession();
}

inline int mbd_rand(void* rng_state, unsigned char* output, size_t len) {
    randomGet(output, len);
    return 0;
}

bool alipan::createSession() {
    std::string msg = "5dde4e1bdf9e4966b387ba58f4b3fdc3:" + cfg::driveClientID + ":" + this->userId + ":0";
    std::string pub_key;

    mbedtls_ecdsa_context ctx_sign;
    mbedtls_ecdsa_init(&ctx_sign);
    // gen secp256k1 keypair
    mbedtls_ecdsa_genkey(&ctx_sign, MBEDTLS_ECP_DP_SECP256K1, mbd_rand, nullptr);
    // mbedtls_ecp_group_load(&ctx_sign.grp, MBEDTLS_ECP_DP_SECP256K1);
    // mbedtls_mpi_read_string(&ctx_sign.d, 16, this->device_id.c_str());
    // mbedtls_ecp_mul(&ctx_sign.grp, &ctx_sign.Q, &ctx_sign.d, &ctx_sign.grp.G, mbd_rand, nullptr);

    // dump public key
    size_t pub_len = 0;
    std::vector<uint8_t> pub(MBEDTLS_ECP_MAX_BYTES, 0);
    mbedtls_ecp_point_write_binary(
        &ctx_sign.grp, &ctx_sign.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &pub_len, pub.data(), pub.size());
    pub_key = util::hexEncode(pub.data(), pub_len);

    // sign message
    unsigned char msg_hash[32];
    mbedtls_sha256_ret((uint8_t*)msg.c_str(), msg.size(), msg_hash, 0);

    mbedtls_mpi r, s;
    std::vector<uint8_t> sigdata(MBEDTLS_ECDSA_MAX_LEN, 0);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_ecdsa_sign(&ctx_sign.grp, &r, &s, &ctx_sign.d, msg_hash, sizeof(msg_hash), mbd_rand, nullptr);

    size_t plen = mbedtls_mpi_size(&r);
    mbedtls_mpi_write_binary(&r, sigdata.data(), plen);
    mbedtls_mpi_write_binary(&s, sigdata.data() + plen, plen);
    sigdata[plen * 2] = 1;
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecdsa_free(&ctx_sign);
    this->signature = util::hexEncode(sigdata.data(), plen * 2 + 1);

    SetSysDeviceNickName nick;
    json_object* post = json_object_new_object();
    if (R_SUCCEEDED(setsysGetDeviceNickname(&nick))) {
        json_object_object_add(post, "deviceName", json_object_new_string(nick.nickname));
    }
    json_object_object_add(post, "modelName", json_object_new_string("Windows客户端"));
    json_object_object_add(post, "pubKey", json_object_new_string(pub_key.c_str()));

    json_object* resp = this->request("/users/v1/users/device/create_session", json_object_get_string(post));
    json_object_put(post);
    if (!resp) return false;

    json_object* success = nullptr;
    bool result = false;
    if (json_object_object_get_ex(resp, "success", &success)) {
        result = json_object_get_boolean(success);
    }
    json_object_put(resp);
    if (!result) return false;

    cfg::driveClientSecret = this->accessToken;
    cfg::saveDriveConfig("alipan");

    printf("create session (%s) result %d\n", nick.nickname, result);
    return this->driveId.empty() ? this->getSelfuser() : true;
}

}  // namespace drive