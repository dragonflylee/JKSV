#include "fs.h"
#include "alipan.h"
#include "cfg.h"
#include "ui.h"
#include "util.h"

drive::gd *fs::gDrive = new drive::alipan();
std::string fs::jksvDriveID;

void fs::driveInit() {
    if (!util::isOnline()) return;

    if (fs::gDrive->tokenIsValid()) {
        fs::gDrive->driveListInit("root");
        jksvDriveID = fs::gDrive->getDirID(JKSV_DRIVE_FOLDER, "root");
        if (jksvDriveID.empty()) {
            jksvDriveID = fs::gDrive->createDir(JKSV_DRIVE_FOLDER, "root");
        } else {
            fs::gDrive->driveListInit(jksvDriveID);
        }
    }
}

void fs::driveExit() {
    if (fs::gDrive) delete gDrive;
}