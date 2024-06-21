#include <gtest/gtest.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include "file_scanner.h"

class FileScannerTest : public ::testing::Test {
protected:
    std::string strTestDir = "test_directory";
    std::string strTestFile1 = "test_directory/testfile1.txt";
    std::string strTestFile2 = "test_directory/testfile2.exe";
    std::string strInvalidPath = "/invalid/path";
    std::string strTestLogFilePath = "logs/test_file_scanner.log";
    std::string strDestinationPath = DESTINATION_PATH;

    std::streambuf* m_cinBuffer;
    std::stringstream m_ssInput;

    // 테스트 시작 전에 호출되며 테스트용 디렉토리와 파일 생성
    void SetUp() override {
        mkdir(strTestDir.c_str(), 0700);
        createTestFile(strTestFile1, "file scan test");
        createTestFile(strTestFile2, "UVODFRYSIHLNWPEJXQZAKCBGMT");
    }

    // 테스트 끝난 후 호출되며 생성된 파일과 디렉토리 삭제 및 정리
    void TearDown() override {
        removeTestFile(strTestFile1);
        removeTestFile(strTestFile2);
        removeTestFile(strDestinationPath + "/testfile1.txt");
        removeTestFile(strDestinationPath + "/testfile2.exe");
        removeTestFile(strTestLogFilePath);
        rmdir(strTestDir.c_str());
    }

    // 테스트 파일 생성
    void createTestFile(const std::string& filePath, const std::string& content) {
        std::ofstream outFile(filePath);
        outFile << content;
        outFile.close();
    }

    // 테스트 파일 삭제
    void removeTestFile(const std::string& filePath) {
        remove(filePath.c_str());
    }

    // 표준 입력을 스트링스트림으로 리다이렉트
    void RedirectInput() {
        m_cinBuffer = std::cin.rdbuf(m_ssInput.rdbuf());
    }

    // 표준 입력을 원래의 콘솔로 복원
    void RestoreInput() {
        std::cin.rdbuf(m_cinBuffer);
    }
};

// StartScan 함수에 대한 테스트
TEST_F(FileScannerTest, StartScanTest) {
    CFileScanner IFileScanner(strTestLogFilePath);

    m_ssInput.str(strTestDir + "\n1\n2\ny\n");
    RedirectInput();
    
    int result = IFileScanner.StartScan();

    RestoreInput();
    EXPECT_EQ(result, SUCCESS_CODE);
}

// 에러 케이스 테스트
TEST_F(FileScannerTest, InvalidPathTest) {
    CFileScanner IFileScanner(strTestLogFilePath);

    m_ssInput.str(strInvalidPath + "\n");
    RedirectInput();

    int result = IFileScanner.StartScan();

    RestoreInput();
    EXPECT_EQ(result, ERROR_PATH_NOT_FOUND);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
