#pragma once

#include "http.h"

#define HEADER_CONTENT_TYPE_APP_JSON "Content-Type: application/json; charset=UTF-8"
#define HEADER_AUTHORIZATION "Authorization: Bearer "

namespace drive {

typedef struct {
    std::string name, id, parent;
    bool isDir = false;
    size_t size;
} gdItem;

class gd {
public:
    virtual ~gd() = default;

    virtual bool refreshToken() { return false; }
    virtual bool tokenIsValid() { return false; }

    void clearDriveList() { driveList.clear(); }
    void driveListAppend(const std::string& _q);
    void getListWithParent(const std::string& _parent, std::vector<drive::gdItem *>& _out);
    virtual void driveListInit(const std::string& _q) = 0;
    virtual std::string createDir(const std::string& _dirName, const std::string& _parent) = 0;
    virtual bool deleteFile(const std::string& _fileID) = 0;
    virtual void uploadFile(
        const std::string& _filename, const std::string& _parent, curlFuncs::curlUpArgs* _upload) = 0;
    virtual bool downloadFile(const std::string& _fileID, curlFuncs::curlDlArgs* _download) = 0;

    bool fileExists(const std::string& _filename, const std::string& _parent);
    virtual std::string getDirID(const std::string& _name, const std::string& _parent = "");

protected:
    std::unordered_map<std::string, gdItem> driveList;
};

}  // namespace drive