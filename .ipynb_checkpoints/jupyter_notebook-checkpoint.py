import matplotlib.pyplot as plt

# 데이터 파일에서 데이터 읽기
def read_usage_data(filename):
    with open(filename, 'r') as file:
        return file.read()

# 시각화 함수 (CPU 사용량)
def visualize_cpu_usage(data):
    lines = data.splitlines()
    timestamps = []
    cpu_usages = []

    for line in lines:
        if line.startswith("## CPU Usage:"):
            continue
        if line.startswith("## Disk Usage:"):
            break
        if line.startswith("CPU"):
            parts = line.split()
            timestamps.append(parts[0])
            cpu_usages.append(float(parts[1]))

    plt.figure(figsize=(10, 6))
    plt.plot(timestamps, cpu_usages, marker='o', linestyle='-', color='b', label='CPU Usage (%)')
    plt.xlabel('Timestamp')
    plt.ylabel('CPU Usage (%)')
    plt.title('CPU Usage over Time')
    plt.xticks(rotation=45)
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()

# 파일에서 데이터 읽기
filename = 'usage_data.txt'
data = read_usage_data(filename)

# CPU 사용량 시각화
visualize_cpu_usage(data)