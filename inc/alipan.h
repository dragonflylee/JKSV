#pragma once

#include "gd.h"
#include <json-c/json.h>

namespace drive {

class alipan : public gd {
public:
    virtual ~alipan();

    bool refreshToken() override;
    bool tokenIsValid() override;

    void driveListInit(const std::string& _q) override;
    std::string createDir(const std::string& _dirName, const std::string& _parent) override;
    bool deleteFile(const std::string& _fileID) override;
    void uploadFile(const std::string& _filename, const std::string& _parent, curlFuncs::curlUpArgs* _upload) override;
    bool downloadFile(const std::string& _fileID, curlFuncs::curlDlArgs* _download) override;

    std::string getDirID(const std::string& _name, const std::string& _parent) override;

private:
    std::string driveId;
    std::string userId;
    std::string signature;

    json_object* request(const std::string& api, const std::string& data);

    bool getSelfuser();
    bool createSession();
};

}  // namespace drive