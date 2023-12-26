import time

try:
    while True:
        # 这里是你的程序运行的主要部分
        print("程序在运行...")
        time.sleep(1)  # 模拟程序执行任务
except KeyboardInterrupt:
    # 当按下 Ctrl+C 时执行的操作
    print("\n收到 Ctrl+C 中止信号，程序将退出...")
    # 执行任何必要的清理操作
    # 比如关闭文件、释放资源等
    # 可以添加更多清理代码
finally:
    # 这部分代码将在try或except块执行完后执行，确保代码的执行
    print("程序退出")
