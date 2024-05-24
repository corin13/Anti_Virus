#pragma once

#include "error_codes.h"

class CLoggingManager {
public:
    int ManageLogLevel();
    int RotateLogs();
    int GenerateLogs();
    int MultiSinkLogger();
    int SetupAsyncLogger();
    int TestMultiThreadedLogging();
    int MeasureAsyncLogPerformance();
    int SetupSyncLogger();
    int MeasureSyncLogPerformance();
    int TestLogging();
};