#include <chrono>
#include <iostream>
#include "logfile_manager.h"
#include "spdlog/async.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/spdlog.h"

// 로그 레벨을 순차적으로 설정하고 로그 메시지를 출력하는 함수
int CLoggingManager::ManageLogLevel(){
    try {
        auto logger = spdlog::default_logger();

        spdlog::set_level(spdlog::level::trace); 
        spdlog::trace("This is a trace message - visible at trace level");

        spdlog::set_level(spdlog::level::debug); 
        spdlog::info("This is an info message - visible at debug level");
        spdlog::debug("This is a debug message - visible at debug level");

        spdlog::set_level(spdlog::level::info);
        spdlog::warn("This is a warning message - visible at info level");
        spdlog::debug("This debug message will not be visible at info level");

        spdlog::set_level(spdlog::level::err);
        spdlog::error("This is an error message - visible at error level");
        spdlog::info("This info message will not be visible at error level");

        spdlog::set_level(spdlog::level::critical);
        spdlog::critical("This is a critical message - visible at critical level");
        spdlog::warn("This warning message will not be visible at critical level"); 
        
        SPDLOG_TRACE("Some trace message with param {}", 42);
        SPDLOG_DEBUG("Some debug message");

        return SUCCESS_CODE;
    } catch (const std::exception& ex) {
        spdlog::error("Exception in ManageLogLevel: {}", ex.what());
        return ERROR_UNKNOWN;
    }
}

// 크기와 개수가 제한된 회전 로그 파일을 설정하고 로거 패턴을 정의하는 함수
int CLoggingManager::RotateLogs() {
    try {
        size_t siMaxSize = 1048576 * 5;
        size_t siMaxFiles = 3;

        auto packetLogger = spdlog::rotating_logger_mt("packetLogger", "logs/packet_transmission.log", siMaxSize, siMaxFiles);
        packetLogger->set_level(spdlog::level::debug);
        packetLogger->set_pattern("[%Y-%m-%d %H:%M:%S] [%l] %v");

        auto maliciousLogger = spdlog::rotating_logger_mt("maliciousLogger", "logs/malicious_ips.log", siMaxSize, siMaxFiles);
        maliciousLogger->set_level(spdlog::level::debug);
        maliciousLogger->set_pattern("[%Y-%m-%d %H:%M:%S] [%l] %v");

        auto detailedLogger = spdlog::rotating_logger_mt("detailedLogger", "logs/detailed_logs.log", siMaxSize, siMaxFiles);
        detailedLogger->set_level(spdlog::level::debug);
        detailedLogger->set_pattern("[%Y-%m-%d %H:%M:%S] [%l] %v");

        return SUCCESS_CODE;
    } catch (const std::exception& ex) {
        spdlog::error("Exception in RotateLogs: {}", ex.what());
        return ERROR_UNKNOWN;
    }
}

// 로그 메시지를 생성하여 로그 파일의 크기를 빠르게 증가시키는 함수
int CLoggingManager::GenerateLogs() {
    try {
        auto logger = spdlog::get("rotatingLogger");
        if (!logger) return ERROR_UNKNOWN;

        for (int i = 0; i < 20000; ++i) {
            logger->info("This is log message number {}", i);
        }

        return SUCCESS_CODE;
    } catch (const std::exception& ex) {
        spdlog::error("Exception in GenerateLogs: {}", ex.what());
        return ERROR_UNKNOWN;
    }
}

// 멀티 싱크 로거를 설정하고 로그 레벨에 맞는 메시지 출력을 확인하는 함수
int CLoggingManager::MultiSinkLogger() {
    try {
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%L%$] [pid %P] [thread %t] [%s:%#] %v");

        auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        consoleSink->set_level(spdlog::level::info);

        auto fileSink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/detailed.log", true);
        fileSink->set_level(spdlog::level::trace);  

        std::vector<spdlog::sink_ptr> sinks {consoleSink, fileSink};
        auto logger = std::make_shared<spdlog::logger>("multiSinkLogger", sinks.begin(), sinks.end());
        logger->set_level(spdlog::level::trace);

        spdlog::register_logger(logger);

        logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%L%$] [pid %P] [thread %t] [%s:%#] %v");

        std::cout << " \n";
        for (int i = 0; i < 5; ++i) {
            logger->trace("Trace level message {}", i);
            logger->debug("Debug level message {}", i);
            logger->info("Info level message {}", i);
            logger->warn("Warning level message {}", i);
            logger->error("Error level message {}", i);
            logger->critical("Critical level message {}", i);
        }
        
        return SUCCESS_CODE;
    } catch (const std::exception& ex) {
        spdlog::error("Exception in MultiSinkLogger: {}", ex.what());
        return ERROR_UNKNOWN;
    }
}

// 비동기 로깅을 설정하는 함수
int CLoggingManager::SetupAsyncLogger() {
    try {
        spdlog::init_thread_pool(8192, 1);

        if (!spdlog::get("asyncFileLogger")) {
            auto fileSink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/async.log", true);
            auto logger = std::make_shared<spdlog::async_logger>("async_file_logger", fileSink, spdlog::thread_pool(), spdlog::async_overflow_policy::block);
            spdlog::register_logger(logger);
        }

        return SUCCESS_CODE;
    } catch (const spdlog::spdlog_ex& ex) {
        return ERROR_UNKNOWN;
    }
}

// 멀티스레드 로깅을 테스트 함수
int CLoggingManager::TestMultiThreadedLogging() {
    try {
        std::vector<std::thread> vecThreads;
        const int nThreads = 4;
        const int nLogsPerThread = 100;

        for (int i = 1; i <= nThreads; ++i) {
            vecThreads.emplace_back([i, nLogsPerThread]() {
                auto logger = spdlog::get("async_file_logger");
                if (!logger) return;

                for (int j = 0; j < nLogsPerThread; ++j) {
                    logger->trace("Thread {} - Trace message {}", i, j);
                    logger->debug("Thread {} - Debug message {}", i, j);
                    logger->info("Thread {} - Log message {}", i, j);
                    logger->warn("Thread {} - Warning message {}", i, j);
                    logger->error("Thread {} - Error message {}", i, j);
                    logger->critical("Thread {} - Critical message {}", i, j);
                }
            });
        }
        for (auto& thread : vecThreads) {
            thread.join();
        }

        return SUCCESS_CODE;
    } catch (const std::exception& ex) {
        spdlog::error("Exception in MultiThreadedLoggingTest: {}", ex.what());  
        return ERROR_UNKNOWN;
    }
}

// 비동기 로딩 시스템의 성능을 측정하기 위한 함수
int CLoggingManager::MeasureAsyncLogPerformance() {
    try {
        auto logger = spdlog::get("async_file_logger");
        if (!logger) {
            spdlog::error("Logger not found");
            return ERROR_UNKNOWN;
        }
        const int nLogs = 10000;

        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < nLogs; ++i) {
            logger->info("This is an asynchronous log message number {}", i);
        }
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;

        std::cout << " " << "\n";
        std::cout << "Logging " << nLogs << " messages took " << elapsed.count() << " seconds using asynchronous logging." << std::endl;

        logger->flush();

        return SUCCESS_CODE;
    } catch (const std::exception& ex) {
        spdlog::error("Exception in MeasureAsyncLoggingPerformance: {}", ex.what());
        return ERROR_UNKNOWN;
    }
}

// 동기 로딩을 설정하는 함수
int CLoggingManager::SetupSyncLogger() {
    try {
        auto fileSink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/sync.log", true);
        auto logger = std::make_shared<spdlog::logger>("syncFileLogger", fileSink);
        spdlog::register_logger(logger);

        return SUCCESS_CODE;
    } catch (const std::exception& ex) {
        spdlog::error("Exception in SetupSyncLogger: {}", ex.what());
        return ERROR_UNKNOWN;
    }
}

// 동기 로딩 시스템의 성능을 측정하기 위한 함수
int CLoggingManager::MeasureSyncLogPerformance() {
    try {
        auto logger = spdlog::get("syncFileLogger");
        if (!logger) {
            spdlog::error("Logger not found");
            return ERROR_UNKNOWN;
        }
        const int nLogs = 10000;

        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < nLogs; ++i) {
            logger->info("This is a synchronous log message number {}", i);
        }
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;

        std::cout << "Logging " << nLogs << " messages took " << elapsed.count() << " seconds using synchronous logging." << std::endl;

        logger->flush();

        return SUCCESS_CODE;
    } catch (const std::exception& ex) {
        spdlog::error("Exception in MeasureSyncLoggingPerformance: {}", ex.what());
        return ERROR_UNKNOWN;
    }
}

// 전체 로깅 시스템을 설정하고 다양한 로깅 테스트를 수행하는 함수
int CLoggingManager::TestLogging(){
    int nResult = ManageLogLevel();
    if (nResult != SUCCESS_CODE) return nResult;

    nResult = RotateLogs();
    if (nResult != SUCCESS_CODE) return nResult;

    nResult = GenerateLogs();
    if (nResult != SUCCESS_CODE) return nResult;

    nResult = MultiSinkLogger();
    if (nResult != SUCCESS_CODE) return nResult;

    nResult = SetupAsyncLogger();
    if (nResult != SUCCESS_CODE) return nResult;

    nResult = TestMultiThreadedLogging();
    if (nResult != SUCCESS_CODE) return nResult;

    spdlog::get("multiSinkLogger")->info("This is an informational message that will appear in console and file.");

    nResult = MeasureAsyncLogPerformance();
    if (nResult != SUCCESS_CODE) return nResult;

    nResult = SetupSyncLogger();
    if (nResult != SUCCESS_CODE) return nResult;

    nResult = MeasureSyncLogPerformance();
    if (nResult != SUCCESS_CODE) return nResult;

    spdlog::shutdown();
    return SUCCESS_CODE;
}