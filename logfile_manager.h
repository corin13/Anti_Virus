#pragma once

#include "error_codes.h"
#include "packet_handler.h"

class CLoggingManager {
public:
    int ManageLogLevel();
    static int RotateLogs();
    static int GenerateLogs(const std::string& loggerName);
    int MultiSinkLogger();
    int SetupAsyncLogger();
    int TestMultiThreadedLogging();
    int MeasureAsyncLogPerformance();
    int SetupSyncLogger();
    int MeasureSyncLogPerformance();
    static int StartRotation();
    static int TestLogging();
};