#include <iostream>
#include "ansi_color.h"
#include "database_manager.h"
#include "util.h"

CDatabaseManager::CDatabaseManager() {
    // 데이터베이스 파일 오픈, 파일 없으면 새로 생성
    if (sqlite3_open(DATABASE_NAME, &m_pDb)) {
        HandleError(ERROR_DATABASE_GENERAL, "Can't open database: " + std::string(sqlite3_errmsg(m_pDb)));
    } else {
        std::cout << COLOR_GREEN <<"Opened database successfully"  << COLOR_RESET << "\n";;
    }
    InitializeDatabase();
}

CDatabaseManager::~CDatabaseManager() {
    if (m_pDb) {
        sqlite3_close(m_pDb);
    }
}

// 데이터베이스 초기화 + 필요한 테이블 생성
void CDatabaseManager::InitializeDatabase() {
    const char* chSql = R"(
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE,
            creation_time TEXT,
            last_modified_time TEXT,
            hash TEXT,
            file_size INTEGER
        );

        CREATE TABLE IF NOT EXISTS file_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            event_time TEXT,
            hash TEXT,
            event_type TEXT,
            file_size INTEGER,
            user TEXT,
            process_id INTEGER
        );
    )";

    ExecuteSQL(chSql);
}

// SQL 쿼리 준비
bool CDatabaseManager::PrepareSQL(const std::string& sql, sqlite3_stmt** stmt) {
    if (sqlite3_prepare_v2(m_pDb, sql.c_str(), -1, stmt, nullptr) != SQLITE_OK) {
        PrintErrorMessage(ERROR_DATABASE_GENERAL, "Failed to prepare statement: " + std::string(sqlite3_errmsg(m_pDb)));
        return false;
    }
    return true;
}

// SQL 쿼리 실행 및 리소스 해제
void CDatabaseManager::FinalizeAndExecuteSQL(sqlite3_stmt* stmt) {
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        PrintErrorMessage(ERROR_DATABASE_GENERAL, "Failed to execute statement: " + std::string(sqlite3_errmsg(m_pDb)));
    }
    sqlite3_finalize(stmt);
}


// 파일 이벤트 발생마다 데이터 추가 및 업데이트
void CDatabaseManager::LogEventToDatabase(const ST_MonitorData& data) {
    sqlite3_stmt* stmt;

    // file_events 테이블에 삽입
    std::string insertEventSql = R"(
        INSERT INTO file_events (file_path, event_time, hash, event_type, file_size, user, process_id)
        VALUES (?, ?, ?, ?, ?, ?, ?);
    )";

    // SQL 쿼리 준비
if (!PrepareSQL(insertEventSql, &stmt)) {
    return;
}

    // SQL 쿼리에 매개변수 바인딩
    sqlite3_bind_text(stmt, 1, data.filePath.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, data.timestamp.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, data.newHash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, data.eventType.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, data.fileSize);
    sqlite3_bind_text(stmt, 6, data.user.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, data.processId);

    // SQL 쿼리 실행
    FinalizeAndExecuteSQL(stmt);

    // files 테이블 업데이트
    if (data.eventType != "File moved from" && data.eventType != "File deleted") {
        std::string updateMainSql = R"(
            INSERT INTO files (file_path, creation_time, last_modified_time, hash, file_size)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(file_path) DO UPDATE SET
                last_modified_time=excluded.last_modified_time,
                hash=excluded.hash,
                file_size=excluded.file_size;
        )";

        if (!PrepareSQL(updateMainSql, &stmt)) {
            return;
        }

        sqlite3_bind_text(stmt, 1, data.filePath.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, data.timestamp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, data.timestamp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, data.newHash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 5, data.fileSize);

        FinalizeAndExecuteSQL(stmt);
    }
}

// SQL 쿼리 실행
void CDatabaseManager::ExecuteSQL(const std::string& sql) {
    char* errMsg = nullptr;
    if (sqlite3_exec(m_pDb, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
        PrintErrorMessage(ERROR_DATABASE_GENERAL, "Failed to execute SQL: " + std::string(errMsg));
        sqlite3_free(errMsg);
    }
}

// 파일 경로에 대한 해시 값을 files 테이블에서 가져옴
std::string CDatabaseManager::GetFileHash(const std::string& filePath) {
    sqlite3_stmt* stmt;
    std::string sql = "SELECT hash FROM files WHERE file_path = ?";

    if (!PrepareSQL(sql, &stmt)) {
        return "";
    }

    sqlite3_bind_text(stmt, 1, filePath.c_str(), -1, SQLITE_STATIC);

    std::string hash;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }

    sqlite3_finalize(stmt);
    return hash;
}

// 특정 파일 경로의 파일 크기 가져옴
int64_t CDatabaseManager::GetFileSize(const std::string& filePath) {
    sqlite3_stmt* stmt;
    std::string sql = "SELECT file_size FROM files WHERE file_path = ?";

    if (!PrepareSQL(sql, &stmt)) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, filePath.c_str(), -1, SQLITE_STATIC);

    int64_t fileSize = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        fileSize = sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return fileSize;
}

// 파일 경로에 대한 데이터를 files 테이블에서 삭제
void CDatabaseManager::RemoveFileFromDatabase(const std::string& filePath) {
    sqlite3_stmt* stmt;
    std::string sql = "DELETE FROM files WHERE file_path = ?";

    if (!PrepareSQL(sql, &stmt)) {
        return;
    }

    sqlite3_bind_text(stmt, 1, filePath.c_str(), -1, SQLITE_STATIC);

    FinalizeAndExecuteSQL(stmt);
}