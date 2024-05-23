#pragma once
#include "spdlog/spdlog.h"

void ManageLogLevel();
void RotateLogs();
void GenerateLogs();
void MultiSinkLogger();
void SetupAsyncLogger();
void MultiThreadedLoggingTest();
void MeasureAsyncLoggingPerformance();
void SetupSyncLogger();
void MeasureSyncLoggingPerformance();
void logging();