#include <iostream>
#include <chrono>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/async.h"
#include "log_manager.h"

void ManageLogLevel(){
    auto logger = spdlog::default_logger();

    // TRACE 레벨 설정
    spdlog::set_level(spdlog::level::trace); // 전역 로그 레벨을 trace로 설정
    spdlog::trace("This is a trace message - visible at trace level");

    // DEBUG 레벨 설정
    spdlog::set_level(spdlog::level::debug); // 전역 로그 레벨을 debug로 설정
    spdlog::info("This is an info message - visible at debug level");
    spdlog::debug("This is a debug message - visible at debug level");

    // INFO 레벨 설정
    spdlog::set_level(spdlog::level::info);
    spdlog::warn("This is a warning message - visible at info level");
    spdlog::debug("This debug message will not be visible at info level");

    // ERROR 레벨 설정
    spdlog::set_level(spdlog::level::err);
    spdlog::error("This is an error message - visible at error level");
    spdlog::info("This info message will not be visible at error level");

    // CRITICAL 레벨 설정
    spdlog::set_level(spdlog::level::critical);
    spdlog::critical("This is a critical message - visible at critical level");
    spdlog::warn("This warning message will not be visible at critical level"); 
    
    SPDLOG_TRACE("Some trace message with param {}", 42);
    SPDLOG_DEBUG("Some debug message");
}

void RotateLogs() {
    size_t max_size = 1048576 * 5;
    size_t max_files = 3;

    auto rotating_logger = spdlog::rotating_logger_mt("rotating_logger", "logs/rotating_log.txt", max_size, max_files);
    
    rotating_logger->set_level(spdlog::level::debug);
    rotating_logger->set_pattern("[%Y-%m-%d %H:%M:%S] [%l] %v");
}

// 로그 메시지를 생성하여 로그 파일의 크기를 빠르게 증가시키는 함수
void GenerateLogs() {
    auto logger = spdlog::get("rotating_logger");

    if (!logger) {
        std::cerr << "Logger not found!" << std::endl;
        return;
    }
    for (int i = 0; i < 20000; ++i) {
        logger->info("This is log message number {}", i);
    }
}

void MultiSinkLogger() {
    // 로그 포매팅
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%L%$] [pid %P] [thread %t] [%s:%#] %v");

    // 정보 이상만 콘솔에 출력
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(spdlog::level::info);

    // 모든 로그 레벨 기록
    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/detailed.log", true);
    file_sink->set_level(spdlog::level::trace);  

    std::vector<spdlog::sink_ptr> sinks {console_sink, file_sink};
    auto logger = std::make_shared<spdlog::logger>("multi_sink_logger", sinks.begin(), sinks.end());
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
}

// 비동기 로깅을 설정하는 함수
void SetupAsyncLogger() {
    try {
        spdlog::init_thread_pool(8192, 1);

        if (!spdlog::get("async_file_logger")) {
            auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/async.log", true);
            auto async_file_logger = std::make_shared<spdlog::async_logger>("async_file_logger", file_sink, spdlog::thread_pool(), spdlog::async_overflow_policy::block);
            spdlog::register_logger(async_file_logger);
        }
    } catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Logger initialization failed: " << ex.what() << std::endl;
    }
}

// 멀티스레드 테스트 함수
void MultiThreadedLoggingTest() {
    std::vector<std::thread> threads;
    const int num_threads = 4;
    const int num_logs_per_thread = 100;

    for (int i = 1; i <= num_threads; ++i) {
        threads.emplace_back([i, num_logs_per_thread]() {
            auto logger = spdlog::get("async_file_logger");
            if (!logger) {
                std::cerr << "Logger not found in thread " << i << std::endl;
                return;
            }

            for (int j = 0; j < num_logs_per_thread; ++j) {
                logger->trace("Thread {} - Trace message {}", i, j);
                logger->debug("Thread {} - Debug message {}", i, j);
                logger->info("Thread {} - Log message {}", i, j);
                logger->warn("Thread {} - Warning message {}", i, j);
                logger->error("Thread {} - Error message {}", i, j);
                logger->critical("Thread {} - Critical message {}", i, j);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }
}

// 비동기 로딩 시스템의 성능을 측정하기 위한 함수
void MeasureAsyncLoggingPerformance() {
    auto logger = spdlog::get("async_file_logger");
    
    if (!logger) {
        std::cerr << "Logger not found" << std::endl;
        return;
    }

    const int num_logs = 10000;

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < num_logs; ++i) {
        logger->info("This is an asynchronous log message number {}", i);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    std::cout << " " << "\n";
    std::cout << "Logging " << num_logs << " messages took " << elapsed.count() << " seconds using asynchronous logging." << std::endl;

    logger->flush();
}

// 동기 로딩을 설정하는 함수
void SetupSyncLogger() {
    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/sync.log", true);
    auto sync_file_logger = std::make_shared<spdlog::logger>("sync_file_logger", file_sink);
    spdlog::register_logger(sync_file_logger);
}

// 동기 로딩 시스템의 성능을 측정하기 위한 함수
void MeasureSyncLoggingPerformance() {
    auto logger = spdlog::get("sync_file_logger");
    if (!logger) {
        std::cerr << "Logger not found" << std::endl;
        return;
    }

    const int num_logs = 10000;

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < num_logs; ++i) {
        logger->info("This is a synchronous log message number {}", i);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    std::cout << "Logging " << num_logs << " messages took " << elapsed.count() << " seconds using synchronous logging." << std::endl;

    logger->flush();
}

void logging(){
    ManageLogLevel();
    RotateLogs();
    GenerateLogs();
    MultiSinkLogger();
    SetupAsyncLogger();
    MultiThreadedLoggingTest();
    spdlog::get("multi_sink_logger")->info("This is an informational message that will appear in console and file.");
    MeasureAsyncLoggingPerformance();
    SetupSyncLogger();
    MeasureSyncLoggingPerformance();
    spdlog::shutdown();
}