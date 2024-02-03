#include "alipan.h"

namespace drive {

void gd::getListWithParent(const std::string& _parent, std::vector<drive::gdItem *>& _out)
{
    _out.clear();
    for(auto& it : this->driveList)
    {
        if(it.second.parent == _parent)
            _out.push_back(&it.second);
    }
}

bool gd::fileExists(const std::string& _filename, const std::string& _parent)
{
    for(auto& it : this->driveList)
    {
        if(!it.second.isDir && it.second.name == _filename)
            return true; 
    }
    return false;
}

std::string gd::getDirID(const std::string& _name, const std::string& _parent)
{
    for(auto& it : this->driveList)
    {
        if(it.second.isDir && it.second.name == _name && it.second.parent == _parent)
            return it.second.id;
    }
    return "";
}

}