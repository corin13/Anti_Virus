#pragma once

#include <sqlite3.h>
#include <string>
#include "event_monitor.h"

#define DATABASE_NAME "file_monitor.db"
#define FILES_TABLE "files"
#define FILE_EVENTS_TABLE "file_events"

struct ST_MonitorData; //전방 선언

class CDatabaseManager {
public:
    CDatabaseManager();
    ~CDatabaseManager();
    
    void InitializeDatabase();
    void LogEventToDatabase(const ST_MonitorData& data);
    std::string GetFileHash(const std::string& filePath);
    void RemoveFileFromDatabase(const std::string& filePath);

private:
    sqlite3* m_pDb;
    void ExecuteSQL(const std::string& sql);
};
