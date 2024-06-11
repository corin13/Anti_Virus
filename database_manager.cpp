#include <iostream>
#include "database_manager.h"
#include "util.h"

CDatabaseManager::CDatabaseManager() {
    // 데이터베이스 파일 오픈, 파일 없으면 새로 생성
    if (sqlite3_open(DATABASE_NAME, &m_pDb)) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(m_pDb) << std::endl;
        exit(EXIT_FAILURE);
    } else {
        std::cout << "Opened database successfully\n";
    }
    InitializeDatabase();
}

CDatabaseManager::~CDatabaseManager() {
    if (m_pDb) {
        sqlite3_close(m_pDb);
    }
}

void CDatabaseManager::InitializeDatabase() {
    const char* chSql = R"(
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE,
            creation_time TEXT,
            last_modified_time TEXT,
            hash TEXT
        );

        CREATE TABLE IF NOT EXISTS file_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            event_time TEXT,
            hash TEXT,
            event_type TEXT,
            file_size INTEGER
        );
    )";

    ExecuteSQL(chSql);
}

void CDatabaseManager::LogEventToDatabase(const ST_MonitorData& data) {
    sqlite3_stmt* stmt;

    // file_events 테이블에 삽입
    std::string insertEventSql = R"(
        INSERT INTO file_events (file_path, event_time, hash, event_type, file_size)
        VALUES (?, ?, ?, ?, ?);
    )";

    // SQL 쿼리 준비
    if (sqlite3_prepare_v2(m_pDb, insertEventSql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_pDb) << std::endl;
        return;
    }

    // SQL 쿼리에 매개변수 바인딩
    sqlite3_bind_text(stmt, 1, data.filePath.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, data.timestamp.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, data.newHash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, data.eventDescription.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, data.fileSize);

    // SQL 쿼리 실행
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to insert event: " << sqlite3_errmsg(m_pDb) << std::endl;
    }

    // SQL문 해제
    sqlite3_finalize(stmt);

    // files 테이블 업데이트
    std::string updateMainSql = R"(
        INSERT INTO files (file_path, creation_time, last_modified_time, hash)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(file_path) DO UPDATE SET
            last_modified_time=excluded.last_modified_time,
            hash=excluded.hash;
    )";

    if (sqlite3_prepare_v2(m_pDb, updateMainSql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_pDb) << std::endl;
        return;
    }

    sqlite3_bind_text(stmt, 1, data.filePath.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, data.timestamp.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, data.timestamp.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, data.newHash.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to update main table: " << sqlite3_errmsg(m_pDb) << std::endl;
    }

    sqlite3_finalize(stmt);
}

void CDatabaseManager::ExecuteSQL(const std::string& sql) {
    char* errMsg = nullptr;
    if (sqlite3_exec(m_pDb, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        exit(EXIT_FAILURE);
    }
}
