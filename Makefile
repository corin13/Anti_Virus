# Makefile 예시

# 컴파일러 설정
CXX=g++

# 컴파일러 플래그 설정
CXXFLAGS=-Wall -Wextra -O2 -std=c++17 -I/usr/local/include/pcapplusplus -I.

# 링커 플래그 설정
LDFLAGS=-lssl -lcrypto -lyara -lpthread -ljsoncpp -lcurl -lpcap -L/usr/local/lib -lPcap++ -lPacket++ -lCommon++ -lsqlite3 -lstdc++fs

# gtest 플래그 추가
GTEST_LDFLAGS=-lgtest -lgtest_main

# 최종 타겟 설정
TARGET=UdkdAgent
TEST_TARGET=RunTests

# 소스 파일과 헤더 파일 찾기
SOURCES=$(wildcard *.cpp)
HEADERS=$(wildcard *.h)
OBJECTS=$(SOURCES:.cpp=.o)

# 테스트 소스 파일과 오브젝트 파일
TEST_SOURCES=$(wildcard test/*.cpp)
TEST_OBJECTS=$(TEST_SOURCES:.cpp=.o)
ALL_TEST_OBJECTS=$(TEST_OBJECTS) $(filter-out main.o, $(OBJECTS))

# 기본 타겟 설정
all: $(TARGET)
	@echo "Build successful!"
	@$(MAKE) clean
	
# 최종 실행 파일 생성 규칙
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) || (echo "Build failed!"; exit 1)

# 소스 파일을 오브젝트 파일로 컴파일
%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@ || (echo "Compilation failed on $<"; exit 1)

# 테스트 실행 규칙
test: $(TEST_TARGET)
	./$(TEST_TARGET)
	@$(MAKE) clean

# 테스트 실행 파일 생성 규칙
$(TEST_TARGET): $(ALL_TEST_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(GTEST_LDFLAGS) $(LDFLAGS) || (echo "Build failed!"; exit 1)

# 'make clean'을 실행할 때 오브젝트 파일 제거
clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS)

# 라이브러리 설치 규칙
install:
	sudo apt-get update
	sudo apt-get install -y libjsoncpp-dev libcurl4-openssl-dev libspdlog-dev sysstat ifstat yara libyara-dev libpcap-dev cmake libsqlite3-dev libssl-dev Jupyter-core git-lfs

.PHONY: clean test