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
            hash TEXT
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

// 파일 이벤트 발생마다 데이터 추가 및 업데이트
void CDatabaseManager::LogEventToDatabase(const ST_MonitorData& data) {
    sqlite3_stmt* stmt;

    // file_events 테이블에 삽입
    std::string insertEventSql = R"(
        INSERT INTO file_events (file_path, event_time, hash, event_type, file_size, user, process_id)
        VALUES (?, ?, ?, ?, ?, ?, ?);
    )";

    // SQL 쿼리 준비
    if (sqlite3_prepare_v2(m_pDb, insertEventSql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        PrintErrorMessage(ERROR_DATABASE_GENERAL, "Failed to prepare statement: " + std::string(sqlite3_errmsg(m_pDb)));
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
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        PrintErrorMessage(ERROR_DATABASE_GENERAL, "Failed to insert event: " + std::string(sqlite3_errmsg(m_pDb)));
    }

    // SQL문 해제
    sqlite3_finalize(stmt);

    // files 테이블 업데이트
    if (data.eventType != "File moved from" && data.eventType != "File deleted") {
        std::string updateMainSql = R"(
            INSERT INTO files (file_path, creation_time, last_modified_time, hash)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(file_path) DO UPDATE SET
                last_modified_time=excluded.last_modified_time,
                hash=excluded.hash;
        )";

        if (sqlite3_prepare_v2(m_pDb, updateMainSql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            PrintErrorMessage(ERROR_DATABASE_GENERAL, "Failed to prepare statement: " + std::string(sqlite3_errmsg(m_pDb)));
            return;
        }

        sqlite3_bind_text(stmt, 1, data.filePath.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, data.timestamp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, data.timestamp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, data.newHash.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            PrintErrorMessage(ERROR_DATABASE_GENERAL, "Failed to update files table: " + std::string(sqlite3_errmsg(m_pDb)));
        }

        sqlite3_finalize(stmt);
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

    if (sqlite3_prepare_v2(m_pDb, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::string strErrorMsg = "Failed to prepare statement: " + std::string(sqlite3_errmsg(m_pDb));
        throw std::runtime_error(strErrorMsg);
    }

    sqlite3_bind_text(stmt, 1, filePath.c_str(), -1, SQLITE_STATIC);

    std::string hash;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }

    if (hash.empty()) {
        return "";
    }

    sqlite3_finalize(stmt);

    return hash;
}

// 파일 경로에 대한 데이터를 files 테이블에서 삭제
void CDatabaseManager::RemoveFileFromDatabase(const std::string& filePath) {
    sqlite3_stmt* stmt;
    std::string sql = "DELETE FROM files WHERE file_path = ?";

    if (sqlite3_prepare_v2(m_pDb, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        PrintErrorMessage(ERROR_DATABASE_GENERAL, "Failed to prepare statement: " + std::string(sqlite3_errmsg(m_pDb)));
        return;
    }

    sqlite3_bind_text(stmt, 1, filePath.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        PrintErrorMessage(ERROR_DATABASE_GENERAL, "Failed to delete file: " + std::string(sqlite3_errmsg(m_pDb)));
        return;
    }

    sqlite3_finalize(stmt);
/*
    // 데이터베이스 변경 사항 커밋
    char* errMsg = nullptr;
    if (sqlite3_exec(m_pDb, "COMMIT;", nullptr, nullptr, &errMsg) != SQLITE_OK) {
        PrintErrorMessage(ERROR_DATABASE_GENERAL, "Failed to commit transaction: " + std::string(errMsg));
        sqlite3_free(errMsg);
        return;
    }
    */
}